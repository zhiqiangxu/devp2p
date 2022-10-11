package devp2p

import (
	"net"

	"github.com/ethereum/go-ethereum/p2p/discover/v4wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

type ExtraConfig struct {
	WireManager WireManager
}

type WireManager interface {
	Decode(input []byte) (v4wire.Packet, v4wire.Pubkey, []byte, error)
	WrapPacket(t *UDPv4, p v4wire.Packet) *PacketHandlerV4

	HandlePendingNeighborsPacket(t *UDPv4, neighborsPacket v4wire.Packet, toaddr *net.UDPAddr) (int, []*enode.Node)
	HandlePendingPongPacket(pongPacket v4wire.Packet, hash []byte, callback func()) (bool, bool)
	HandlePendingENRResponsePacket(pongPacket v4wire.Packet, hash []byte) (bool, bool)

	PingPacket(self *enode.Node, toaddr *net.UDPAddr) v4wire.Packet
	ENRRequestPacket() v4wire.Packet
	FindnodePacket(target v4wire.Pubkey) v4wire.Packet

	PongPacketType() byte
	NeighborsPacketType() byte
	ENRResponsePacketType() byte

	Resolve(n *enode.Node) *enode.Node
}

type ethWireManager struct {
}

func (w *ethWireManager) Decode(input []byte) (v4wire.Packet, v4wire.Pubkey, []byte, error) {
	return v4wire.Decode(input)
}

func (w *ethWireManager) WrapPacket(t *UDPv4, p v4wire.Packet) *PacketHandlerV4 {

	return nil
}

func (w *ethWireManager) HandlePendingNeighborsPacket(t *UDPv4, neighborsPacket v4wire.Packet, toaddr *net.UDPAddr) (int, []*enode.Node) {
	return 0, nil
}

func (w *ethWireManager) HandlePendingPongPacket(pongPacket v4wire.Packet, hash []byte, callback func()) (bool, bool) {
	return false, false
}

func (w *ethWireManager) HandlePendingENRResponsePacket(pongPacket v4wire.Packet, hash []byte) (bool, bool) {
	return false, false
}

func (w *ethWireManager) PingPacket(self *enode.Node, toaddr *net.UDPAddr) v4wire.Packet {
	return nil
}

func (w *ethWireManager) ENRRequestPacket() v4wire.Packet {
	return nil
}

func (w *ethWireManager) FindnodePacket(target v4wire.Pubkey) v4wire.Packet {
	return nil
}

func (w *ethWireManager) PongPacketType() byte {
	return v4wire.PongPacket
}

func (w *ethWireManager) NeighborsPacketType() byte {
	return v4wire.NeighborsPacket
}

func (w *ethWireManager) ENRResponsePacketType() byte {
	return v4wire.ENRResponsePacket
}

func (w *ethWireManager) Resolve(n *enode.Node) *enode.Node {
	return nil
}
