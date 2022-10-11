package devp2p

import (
	"crypto/ecdsa"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Node represents a host on the network.
// The fields of Node may not be modified.
type Node struct {
	enode.Node
	addedAt        time.Time // time when the node was added to the table
	livenessChecks uint      // how often liveness was checked
}

type encPubkey [64]byte

func encodePubkey(key *ecdsa.PublicKey) encPubkey {
	var e encPubkey
	math.ReadBits(key.X, e[:len(e)/2])
	math.ReadBits(key.Y, e[len(e)/2:])
	return e
}

func WrapNode(n *enode.Node) *Node {
	return &Node{Node: *n}
}

func wrapNodes(ns []*enode.Node) []*Node {
	result := make([]*Node, len(ns))
	for i, n := range ns {
		result[i] = WrapNode(n)
	}
	return result
}

func unwrapNode(n *Node) *enode.Node {
	return &n.Node
}

func unwrapNodes(ns []*Node) []*enode.Node {
	result := make([]*enode.Node, len(ns))
	for i, n := range ns {
		result[i] = unwrapNode(n)
	}
	return result
}

func (n *Node) addr() *net.UDPAddr {
	return &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
}

func (n *Node) String() string {
	return n.Node.String()
}
