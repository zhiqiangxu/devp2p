package devp2p

import (
	"bytes"
	"container/list"
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/discover/v4wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

// Errors
var (
	ErrExpired          = errors.New("expired")
	ErrUnsolicitedReply = errors.New("unsolicited reply")
	ErrUnknownNode      = errors.New("unknown node")
	ErrTimeout          = errors.New("RPC timeout")
	ErrClockWarp        = errors.New("reply deadline too far in the future")
	ErrClosed           = errors.New("socket closed")
	ErrLowPort          = errors.New("low port")
)

const (
	respTimeout    = 500 * time.Millisecond
	expiration     = 20 * time.Second
	bondExpiration = 24 * time.Hour

	maxFindnodeFailures = 5                // nodes exceeding this limit are dropped
	ntpFailureThreshold = 32               // Continuous timeouts after which to check NTP
	ntpWarningCooldown  = 10 * time.Minute // Minimum amount of time to pass before repeating NTP warning
	driftThreshold      = 10 * time.Second // Allowed clock drift before warning user

	// Discovery packets are defined to be no larger than 1280 bytes.
	// Packets larger than this size will be cut at the end and treated
	// as invalid because their hash won't match.
	maxPacketSize = 1280
)

func ListenV4(c discover.UDPConn, ln *enode.LocalNode, cfg discover.Config, extraCfg ExtraConfig) (*UDPv4, error) {
	if extraCfg.WireManager == nil {
		extraCfg.WireManager = &ethWireManager{}
	}
	cfg = withDefaults(cfg)
	closeCtx, cancel := context.WithCancel(context.Background())
	t := &UDPv4{
		Config:          cfg,
		ExtraConfig:     extraCfg,
		conn:            c,
		LocalNode:       ln,
		DB:              ln.Database(),
		gotreply:        make(chan reply),
		addReplyMatcher: make(chan *replyMatcher),
		closeCtx:        closeCtx,
		cancelCloseCtx:  cancel,
	}
	tab, err := newTable(t, ln.Database(), cfg.Bootnodes, t.Log)
	if err != nil {
		return nil, err
	}
	t.Tab = tab
	go tab.loop()

	t.wg.Add(2)
	go t.loop()
	go t.readLoop(cfg.Unhandled)
	return t, nil
}

func withDefaults(cfg discover.Config) discover.Config {
	if cfg.Log == nil {
		cfg.Log = log.Root()
	}
	if cfg.ValidSchemes == nil {
		cfg.ValidSchemes = enode.ValidSchemes
	}
	if cfg.Clock == nil {
		cfg.Clock = mclock.System{}
	}
	return cfg
}

// UDPv4 implements the v4 wire protocol.
type UDPv4 struct {
	discover.Config
	ExtraConfig
	conn      discover.UDPConn
	LocalNode *enode.LocalNode
	DB        *enode.DB
	Tab       *Table
	closeOnce sync.Once
	wg        sync.WaitGroup

	addReplyMatcher chan *replyMatcher
	gotreply        chan reply
	closeCtx        context.Context
	cancelCloseCtx  context.CancelFunc
}

// HandleReply dispatches a reply packet, invoking reply matchers. It returns
// whether any matcher considered the packet acceptable.
func (t *UDPv4) HandleReply(from enode.ID, fromIP net.IP, req v4wire.Packet) bool {
	matched := make(chan bool, 1)
	select {
	case t.gotreply <- reply{from, fromIP, req, matched}:
		// loop will handle it
		return <-matched
	case <-t.closeCtx.Done():
		return false
	}
}

// loop runs in its own goroutine. it keeps track of
// the refresh timer and the pending reply queue.
func (t *UDPv4) loop() {
	defer t.wg.Done()

	var (
		plist        = list.New()
		timeout      = time.NewTimer(0)
		nextTimeout  *replyMatcher // head of plist when timeout was last reset
		contTimeouts = 0           // number of continuous timeouts to do NTP checks
		ntpWarnTime  = time.Unix(0, 0)
	)
	<-timeout.C // ignore first timeout
	defer timeout.Stop()

	resetTimeout := func() {
		if plist.Front() == nil || nextTimeout == plist.Front().Value {
			return
		}
		// Start the timer so it fires when the next pending reply has expired.
		now := time.Now()
		for el := plist.Front(); el != nil; el = el.Next() {
			nextTimeout = el.Value.(*replyMatcher)
			if dist := nextTimeout.deadline.Sub(now); dist < 2*respTimeout {
				timeout.Reset(dist)
				return
			}
			// Remove pending replies whose deadline is too far in the
			// future. These can occur if the system clock jumped
			// backwards after the deadline was assigned.
			nextTimeout.errc <- ErrClockWarp
			plist.Remove(el)
		}
		nextTimeout = nil
		timeout.Stop()
	}

	for {
		resetTimeout()

		select {
		case <-t.closeCtx.Done():
			for el := plist.Front(); el != nil; el = el.Next() {
				el.Value.(*replyMatcher).errc <- ErrClosed
			}
			return

		case p := <-t.addReplyMatcher:
			p.deadline = time.Now().Add(respTimeout)
			plist.PushBack(p)

		case r := <-t.gotreply:
			var matched bool // whether any replyMatcher considered the reply acceptable.
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*replyMatcher)
				if p.from == r.from && p.ptype == r.data.Kind() && p.ip.Equal(r.ip) {
					ok, requestDone := p.callback(r.data)
					matched = matched || ok
					p.reply = r.data
					// Remove the matcher if callback indicates that all replies have been received.
					if requestDone {
						p.errc <- nil
						plist.Remove(el)
					}
					// Reset the continuous timeout counter (time drift detection)
					contTimeouts = 0
				}
			}
			r.matched <- matched

		case now := <-timeout.C:
			nextTimeout = nil

			// Notify and remove callbacks whose deadline is in the past.
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*replyMatcher)
				if now.After(p.deadline) || now.Equal(p.deadline) {
					p.errc <- ErrTimeout
					plist.Remove(el)
					contTimeouts++
				}
			}
			// If we've accumulated too many timeouts, do an NTP time sync check
			if contTimeouts > ntpFailureThreshold {
				if time.Since(ntpWarnTime) >= ntpWarningCooldown {
					ntpWarnTime = time.Now()
					go checkClockDrift()
				}
				contTimeouts = 0
			}
		}
	}
}

// readLoop runs in its own goroutine. it handles incoming UDP packets.
func (t *UDPv4) readLoop(unhandled chan<- discover.ReadPacket) {
	defer t.wg.Done()
	if unhandled != nil {
		defer close(unhandled)
	}

	buf := make([]byte, maxPacketSize)
	for {
		nbytes, from, err := t.conn.ReadFromUDP(buf)
		if netutil.IsTemporaryError(err) {
			// Ignore temporary read errors.
			t.Log.Debug("Temporary UDP read error", "err", err)
			continue
		} else if err != nil {
			// Shut down the loop for permament errors.
			if !errors.Is(err, io.EOF) {
				t.Log.Debug("UDP read error", "err", err)
			}
			return
		}
		if t.handlePacket(from, buf[:nbytes]) != nil && unhandled != nil {
			select {
			case unhandled <- discover.ReadPacket{Data: buf[:nbytes], Addr: from}:
			default:
			}
		}
	}
}

func (t *UDPv4) handlePacket(from *net.UDPAddr, buf []byte) error {
	rawpacket, fromKey, hash, err := t.WireManager.Decode(buf)
	if err != nil {
		rawpacket, fromKey, hash, err = v4wire.Decode(buf)
		if err != nil {
			t.Log.Debug("Bad discv4 packet", "addr", from, "err", err)
			return err
		}
	}

	packet := t.WireManager.WrapPacket(t, rawpacket)
	if packet == nil {
		packet = t.wrapPacket(rawpacket)
	}

	fromID := fromKey.ID()
	if err == nil && packet.Preverify != nil {
		err = packet.Preverify(packet, from, fromID, fromKey)
	}
	t.Log.Trace("<< "+packet.Name(), "id", fromID, "addr", from, "err", err)
	if err == nil && packet.Handle != nil {
		packet.Handle(packet, from, fromID, hash)
	}
	return err
}

// PacketHandlerV4 wraps a packet with handler functions.
type PacketHandlerV4 struct {
	v4wire.Packet
	SenderKey *ecdsa.PublicKey // used for ping

	// Preverify checks whether the packet is valid and should be handled at all.
	Preverify func(p *PacketHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error
	// Handle handles the packet.
	Handle func(h *PacketHandlerV4, from *net.UDPAddr, fromID enode.ID, mac []byte)
}

// wrapPacket returns the handler functions applicable to a packet.
func (t *UDPv4) wrapPacket(p v4wire.Packet) *PacketHandlerV4 {
	var h PacketHandlerV4
	h.Packet = p
	switch p.(type) {
	case *v4wire.Ping:
		h.Preverify = t.verifyPing
		h.Handle = t.handlePing
	case *v4wire.Pong:
		h.Preverify = t.verifyPong
	case *v4wire.Findnode:
		h.Preverify = t.verifyFindnode
		h.Handle = t.handleFindnode
	case *v4wire.Neighbors:
		h.Preverify = t.verifyNeighbors
	case *v4wire.ENRRequest:
		h.Preverify = t.verifyENRRequest
		h.Handle = t.handleENRRequest
	case *v4wire.ENRResponse:
		h.Preverify = t.verifyENRResponse
	}
	return &h
}

// Self returns the local node.
func (t *UDPv4) Self() *enode.Node {
	return t.LocalNode.Node()
}

// Close shuts down the socket and aborts any running queries.
func (t *UDPv4) Close() {
	t.closeOnce.Do(func() {
		t.cancelCloseCtx()
		t.conn.Close()
		t.wg.Wait()
		t.Tab.close()
	})
}

// Resolve searches for a specific node with the given ID and tries to get the most recent
// version of the node record for it. It returns n if the node could not be resolved.
func (t *UDPv4) Resolve(n *enode.Node) *enode.Node {
	rn := t.WireManager.Resolve(n)
	if rn != nil {
		return rn
	}
	// Try asking directly. This works if the node is still responding on the endpoint we have.
	if rn, err := t.RequestENR(n); err == nil {
		return rn
	}
	// Check table for the ID, we might have a newer version there.
	if intable := t.Tab.getNode(n.ID()); intable != nil && intable.Seq() > n.Seq() {
		n = intable
		if rn, err := t.RequestENR(n); err == nil {
			return rn
		}
	}
	// Otherwise perform a network lookup.
	var key enode.Secp256k1
	if n.Load(&key) != nil {
		return n // no secp256k1 key
	}
	result := t.LookupPubkey((*ecdsa.PublicKey)(&key))
	for _, rn := range result {
		if rn.ID() == n.ID() {
			if rn, err := t.RequestENR(rn); err == nil {
				return rn
			}
		}
	}
	return n
}

// lookupSelf implements transport.
func (t *UDPv4) lookupSelf() []*enode.Node {
	return t.newLookup(t.closeCtx, encodePubkey(&t.PrivateKey.PublicKey)).run()
}

// RandomNodes is an iterator yielding nodes from a random walk of the DHT.
func (t *UDPv4) RandomNodes() enode.Iterator {
	return newLookupIterator(t.closeCtx, t.newRandomLookup)
}

// lookupRandom implements transport.
func (t *UDPv4) lookupRandom() []*enode.Node {
	return t.newRandomLookup(t.closeCtx).run()
}

// LookupPubkey finds the closest nodes to the given public key.
func (t *UDPv4) LookupPubkey(key *ecdsa.PublicKey) []*enode.Node {
	if t.Tab.len() == 0 {
		// All nodes were dropped, refresh. The very first query will hit this
		// case and run the bootstrapping logic.
		<-t.Tab.refresh()
	}
	return t.newLookup(t.closeCtx, encodePubkey(key)).run()
}

func (t *UDPv4) newRandomLookup(ctx context.Context) *lookup {
	var target encPubkey
	crand.Read(target[:])
	return t.newLookup(ctx, target)
}

func (t *UDPv4) newLookup(ctx context.Context, targetKey encPubkey) *lookup {
	target := enode.ID(crypto.Keccak256Hash(targetKey[:]))
	ekey := v4wire.Pubkey(targetKey)
	it := newLookup(ctx, t.Tab, target, func(n *Node) ([]*Node, error) {
		return t.findnode(n.ID(), n.addr(), ekey)
	})
	return it
}

// findnode sends a findnode request to the given node and waits until
// the node has sent up to k neighbors.
func (t *UDPv4) findnode(toid enode.ID, toaddr *net.UDPAddr, target v4wire.Pubkey) ([]*Node, error) {
	t.ensureBond(toid, toaddr)

	// Add a matcher for 'neighbours' replies to the pending reply queue. The matcher is
	// active until enough nodes have been received.
	nodes := make([]*Node, 0, BucketSize)
	nreceived := 0
	rm := t.pending(toid, toaddr.IP, t.WireManager.NeighborsPacketType(), func(r v4wire.Packet) (matched bool, requestDone bool) {
		if reply, ok := r.(*v4wire.Neighbors); ok {
			for _, rn := range reply.Nodes {
				nreceived++
				n, err := t.nodeFromRPC(toaddr, rn)
				if err != nil {
					t.Log.Trace("Invalid neighbor node received", "ip", rn.IP, "addr", toaddr, "err", err)
					continue
				}
				nodes = append(nodes, n)
			}
		} else {
			received, validNodes := t.WireManager.HandlePendingNeighborsPacket(t, r, toaddr)
			nreceived += received
			for _, node := range validNodes {
				nodes = append(nodes, WrapNode(node))
			}
		}

		return true, nreceived >= BucketSize
	})
	p := t.WireManager.FindnodePacket(target)
	if p == nil {
		p = &v4wire.Findnode{
			Target:     target,
			Expiration: uint64(time.Now().Add(expiration).Unix()),
		}
	}
	t.Send(toaddr, toid, p)
	// Ensure that callers don't see a timeout if the node actually responded. Since
	// findnode can receive more than one neighbors response, the reply matcher will be
	// active until the remote node sends enough nodes. If the remote end doesn't have
	// enough nodes the reply matcher will time out waiting for the second reply, but
	// there's no need for an error in that case.
	err := <-rm.errc
	if errors.Is(err, ErrTimeout) && rm.reply != nil {
		err = nil
	}
	return nodes, err
}

func (t *UDPv4) Send(toaddr *net.UDPAddr, toid enode.ID, req v4wire.Packet) ([]byte, error) {
	packet, hash, err := v4wire.Encode(t.PrivateKey, req)
	if err != nil {
		return hash, err
	}
	return hash, t.write(toaddr, toid, req.Name(), packet)
}

func (t *UDPv4) write(toaddr *net.UDPAddr, toid enode.ID, what string, packet []byte) error {
	_, err := t.conn.WriteToUDP(packet, toaddr)
	t.Log.Trace(">> "+what, "id", toid, "addr", toaddr, "err", err)
	return err
}

func (t *UDPv4) makePing(toaddr *net.UDPAddr) *v4wire.Ping {
	return &v4wire.Ping{
		Version:    4,
		From:       t.ourEndpoint(),
		To:         v4wire.NewEndpoint(toaddr, 0),
		Expiration: uint64(time.Now().Add(expiration).Unix()),
		ENRSeq:     t.LocalNode.Node().Seq(),
	}
}

// ping sends a ping message to the given node and waits for a reply.
func (t *UDPv4) ping(n *enode.Node) (pong v4wire.Packet, err error) {
	rm := t.SendPing(n.ID(), &net.UDPAddr{IP: n.IP(), Port: n.UDP()}, nil)
	if err = <-rm.errc; err == nil {
		pong = rm.reply
	}
	return
}

func (t *UDPv4) ourEndpoint() v4wire.Endpoint {
	n := t.Self()
	a := &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
	return v4wire.NewEndpoint(a, uint16(n.TCP()))
}

func (t *UDPv4) nodeFromRPC(sender *net.UDPAddr, rn v4wire.Node) (*Node, error) {
	if rn.UDP <= 1024 {
		return nil, ErrLowPort
	}
	if err := netutil.CheckRelayIP(sender.IP, rn.IP); err != nil {
		return nil, err
	}
	if t.NetRestrict != nil && !t.NetRestrict.Contains(rn.IP) {
		return nil, errors.New("not contained in netrestrict list")
	}
	key, err := v4wire.DecodePubkey(crypto.S256(), rn.ID)
	if err != nil {
		return nil, err
	}
	n := WrapNode(enode.NewV4(key, rn.IP, int(rn.TCP), int(rn.UDP)))
	err = n.ValidateComplete()
	return n, err
}

func nodeToRPC(n *Node) v4wire.Node {
	var key ecdsa.PublicKey
	var ekey v4wire.Pubkey
	if err := n.Load((*enode.Secp256k1)(&key)); err == nil {
		ekey = v4wire.EncodePubkey(&key)
	}
	return v4wire.Node{ID: ekey, IP: n.IP(), UDP: uint16(n.UDP()), TCP: uint16(n.TCP())}
}

// SendPing sends a ping message to the given node and invokes the callback
// when the reply arrives.
func (t *UDPv4) SendPing(toid enode.ID, toaddr *net.UDPAddr, callback func()) *replyMatcher {

	req := t.WireManager.PingPacket(t.Self(), toaddr)
	if req == nil {
		req = t.makePing(toaddr)
	}
	packet, hash, err := v4wire.Encode(t.PrivateKey, req)
	if err != nil {
		errc := make(chan error, 1)
		errc <- err
		return &replyMatcher{errc: errc}
	}
	// Add a matcher for the reply to the pending reply queue. Pongs are matched if they
	// reference the ping we're about to send.
	rm := t.pending(toid, toaddr.IP, t.WireManager.PongPacketType(), func(p v4wire.Packet) (matched bool, requestDone bool) {
		if _, ok := p.(*v4wire.Pong); ok {
			matched = bytes.Equal(p.(*v4wire.Pong).ReplyTok, hash)
			if matched && callback != nil {
				callback()
			}
			return matched, matched
		} else {
			return t.WireManager.HandlePendingPongPacket(p, hash, callback)
		}

	})
	// Send the packet.
	t.LocalNode.UDPContact(toaddr)
	t.write(toaddr, toid, req.Name(), packet)
	return rm
}

// RequestENR sends enrRequest to the given node and waits for a response.
func (t *UDPv4) RequestENR(n *enode.Node) (*enode.Node, error) {
	addr := &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
	t.ensureBond(n.ID(), addr)

	req := t.WireManager.ENRRequestPacket()
	if req == nil {
		req = &v4wire.ENRRequest{
			Expiration: uint64(time.Now().Add(expiration).Unix()),
		}
	}

	packet, hash, err := v4wire.Encode(t.PrivateKey, req)
	if err != nil {
		return nil, err
	}

	// Add a matcher for the reply to the pending reply queue. Responses are matched if
	// they reference the request we're about to send.
	rm := t.pending(n.ID(), addr.IP, t.WireManager.ENRResponsePacketType(), func(r v4wire.Packet) (matched bool, requestDone bool) {
		if _, ok := r.(*v4wire.ENRResponse); ok {
			matched = bytes.Equal(r.(*v4wire.ENRResponse).ReplyTok, hash)
			return matched, matched
		} else {
			return t.WireManager.HandlePendingENRResponsePacket(r, hash)
		}
	})
	// Send the packet and wait for the reply.
	t.write(addr, n.ID(), req.Name(), packet)
	if err := <-rm.errc; err != nil {
		return nil, err
	}
	// Verify the response record.
	respN, err := enode.New(enode.ValidSchemes, &rm.reply.(*v4wire.ENRResponse).Record)
	if err != nil {
		return nil, err
	}
	if respN.ID() != n.ID() {
		return nil, fmt.Errorf("invalid ID in response record")
	}
	if respN.Seq() < n.Seq() {
		return n, nil // response record is older
	}
	if err := netutil.CheckRelayIP(addr.IP, respN.IP()); err != nil {
		return nil, fmt.Errorf("invalid IP in response record: %v", err)
	}
	return respN, nil
}

// pending adds a reply matcher to the pending reply queue.
// see the documentation of type replyMatcher for a detailed explanation.
func (t *UDPv4) pending(id enode.ID, ip net.IP, ptype byte, callback replyMatchFunc) *replyMatcher {
	ch := make(chan error, 1)
	p := &replyMatcher{from: id, ip: ip, ptype: ptype, callback: callback, errc: ch}
	select {
	case t.addReplyMatcher <- p:
		// loop will handle it
	case <-t.closeCtx.Done():
		ch <- ErrClosed
	}
	return p
}

// CheckBond checks if the given node has a recent enough endpoint proof.
func (t *UDPv4) CheckBond(id enode.ID, ip net.IP) bool {
	return time.Since(t.DB.LastPongReceived(id, ip)) < bondExpiration
}

// ensureBond solicits a ping from a node if we haven't seen a ping from it for a while.
// This ensures there is a valid endpoint proof on the remote end.
func (t *UDPv4) ensureBond(toid enode.ID, toaddr *net.UDPAddr) {
	tooOld := time.Since(t.DB.LastPingReceived(toid, toaddr.IP)) > bondExpiration
	if tooOld || t.DB.FindFails(toid, toaddr.IP) > maxFindnodeFailures {
		rm := t.SendPing(toid, toaddr, nil)
		<-rm.errc
		// Wait for them to ping back and process our pong.
		time.Sleep(respTimeout)
	}
}

// PING/v4

func (t *UDPv4) verifyPing(h *PacketHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.Ping)

	senderKey, err := v4wire.DecodePubkey(crypto.S256(), fromKey)
	if err != nil {
		return err
	}
	if v4wire.Expired(req.Expiration) {
		return ErrExpired
	}
	h.SenderKey = senderKey
	return nil
}

func (t *UDPv4) handlePing(h *PacketHandlerV4, from *net.UDPAddr, fromID enode.ID, mac []byte) {
	req := h.Packet.(*v4wire.Ping)

	// Reply.
	t.Send(from, fromID, &v4wire.Pong{
		To:         v4wire.NewEndpoint(from, req.From.TCP),
		ReplyTok:   mac,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
		ENRSeq:     t.LocalNode.Node().Seq(),
	})

	// Ping back if our last pong on file is too far in the past.
	n := WrapNode(enode.NewV4(h.SenderKey, from.IP, int(req.From.TCP), from.Port))
	if time.Since(t.DB.LastPongReceived(n.ID(), from.IP)) > bondExpiration {
		t.SendPing(fromID, from, func() {
			t.Tab.AddVerifiedNode(n)
		})
	} else {
		t.Tab.AddVerifiedNode(n)
	}

	// Update node database and endpoint predictor.
	t.DB.UpdateLastPingReceived(n.ID(), from.IP, time.Now())
	t.LocalNode.UDPEndpointStatement(from, &net.UDPAddr{IP: req.To.IP, Port: int(req.To.UDP)})
}

// PONG/v4

func (t *UDPv4) verifyPong(h *PacketHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.Pong)

	if v4wire.Expired(req.Expiration) {
		return ErrExpired
	}
	if !t.HandleReply(fromID, from.IP, req) {
		return ErrUnsolicitedReply
	}
	t.LocalNode.UDPEndpointStatement(from, &net.UDPAddr{IP: req.To.IP, Port: int(req.To.UDP)})
	t.DB.UpdateLastPongReceived(fromID, from.IP, time.Now())
	return nil
}

// FINDNODE/v4

func (t *UDPv4) verifyFindnode(h *PacketHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.Findnode)

	if v4wire.Expired(req.Expiration) {
		return ErrExpired
	}
	if !t.CheckBond(fromID, from.IP) {
		// No endpoint proof pong exists, we don't process the packet. This prevents an
		// attack vector where the discovery protocol could be used to amplify traffic in a
		// DDOS attack. A malicious actor would send a findnode request with the IP address
		// and UDP port of the target as the source address. The recipient of the findnode
		// packet would then send a neighbors packet (which is a much bigger packet than
		// findnode) to the victim.
		return ErrUnknownNode
	}
	return nil
}

func (t *UDPv4) handleFindnode(h *PacketHandlerV4, from *net.UDPAddr, fromID enode.ID, mac []byte) {
	req := h.Packet.(*v4wire.Findnode)

	// Determine closest nodes.
	target := enode.ID(crypto.Keccak256Hash(req.Target[:]))
	closest := t.Tab.FindnodeByID(target, BucketSize, true)

	// Send neighbors in chunks with at most maxNeighbors per packet
	// to stay below the packet size limit.
	p := v4wire.Neighbors{Expiration: uint64(time.Now().Add(expiration).Unix())}
	var sent bool
	for _, n := range closest {
		if netutil.CheckRelayIP(from.IP, n.IP()) == nil {
			p.Nodes = append(p.Nodes, nodeToRPC(n))
		}
		if len(p.Nodes) == v4wire.MaxNeighbors {
			t.Send(from, fromID, &p)
			p.Nodes = p.Nodes[:0]
			sent = true
		}
	}
	if len(p.Nodes) > 0 || !sent {
		t.Send(from, fromID, &p)
	}
}

// NEIGHBORS/v4

func (t *UDPv4) verifyNeighbors(h *PacketHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.Neighbors)

	if v4wire.Expired(req.Expiration) {
		return ErrExpired
	}
	if !t.HandleReply(fromID, from.IP, h.Packet) {
		return ErrUnsolicitedReply
	}
	return nil
}

// ENRREQUEST/v4

func (t *UDPv4) verifyENRRequest(h *PacketHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.ENRRequest)

	if v4wire.Expired(req.Expiration) {
		return ErrExpired
	}
	if !t.CheckBond(fromID, from.IP) {
		return ErrUnknownNode
	}
	return nil
}

func (t *UDPv4) handleENRRequest(h *PacketHandlerV4, from *net.UDPAddr, fromID enode.ID, mac []byte) {
	t.Send(from, fromID, &v4wire.ENRResponse{
		ReplyTok: mac,
		Record:   *t.LocalNode.Node().Record(),
	})
}

// ENRRESPONSE/v4

func (t *UDPv4) verifyENRResponse(h *PacketHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error {
	if !t.HandleReply(fromID, from.IP, h.Packet) {
		return ErrUnsolicitedReply
	}
	return nil
}

// replyMatcher represents a pending reply.
//
// Some implementations of the protocol wish to send more than one
// reply packet to findnode. In general, any neighbors packet cannot
// be matched up with a specific findnode packet.
//
// Our implementation handles this by storing a callback function for
// each pending reply. Incoming packets from a node are dispatched
// to all callback functions for that node.
type replyMatcher struct {
	// these fields must match in the reply.
	from  enode.ID
	ip    net.IP
	ptype byte

	// time when the request must complete
	deadline time.Time

	// callback is called when a matching reply arrives. If it returns matched == true, the
	// reply was acceptable. The second return value indicates whether the callback should
	// be removed from the pending reply queue. If it returns false, the reply is considered
	// incomplete and the callback will be invoked again for the next matching reply.
	callback replyMatchFunc

	// errc receives nil when the callback indicates completion or an
	// error if no further reply is received within the timeout.
	errc chan error

	// reply contains the most recent reply. This field is safe for reading after errc has
	// received a value.
	reply v4wire.Packet
}

type replyMatchFunc func(v4wire.Packet) (matched bool, requestDone bool)

// reply is a reply packet from a certain node.
type reply struct {
	from enode.ID
	ip   net.IP
	data v4wire.Packet
	// loop indicates whether there was
	// a matching request by sending on this channel.
	matched chan<- bool
}
