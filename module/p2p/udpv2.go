package p2p

import (
	"encoding/binary"
)

// Android libp2p.so UDP control-channel protocol, recovered from
// UDPServer::HandleClientData @0xe1e4c, CheckNATE @0xe0840,
// OnAckHeartBeat @0xe22a4 and OnACKNATProbe @0xe26f0 (docs §10.62).
//
// Wire layout of the 9-byte control header:
//
//	+0  u8   packet class: 1 or 3 => control, otherwise Swordfish stream
//	+1  u8   command
//	+2  u16  LE payload length (bytes after the header)
//	+4  u8   sequence (low byte of the global msgNo counter)
//	+5  u32  LE uid (P2PCenter::GetUID)
//
// Payload starts at offset +9. There is no standalone heartbeat request in
// this protocol generation: the NAT probe (0x29) doubles as keepalive and the
// tracker answers with 0x30 (TNATProbeMsg) and/or 0x27 (heartbeat ACK).

// Control packet commands.
const (
	CmdPassiveConnect = 0x13 // server -> client: punch instruction
	CmdRelayPunch     = 0x0a // client -> tracker via newReqRelayMsg
	CmdHeartbeatACK   = 0x27 // server -> client: ACK_HEARTBEAT_INFO
	CmdNATProbe       = 0x29 // client -> help servers (keepalive)
	CmdNATProbeACK    = 0x30 // server -> client: TNATProbeMsg
)

// DefaultHelpServers mirrors the built-in defaults of P2P_HelpSvr1/2
// (uh1.kuwo.cn:6702, uh2.kuwo.cn:6721).
var DefaultHelpServers = []string{
	"uh1.kuwo.cn:6702",
	"uh2.kuwo.cn:6721",
}

// BuildControlPacket renders a control datagram: header plus payload.
func BuildControlPacket(class, cmd byte, seq uint8, uid uint32, payload []byte) []byte {
	b := make([]byte, 9+len(payload))
	b[0] = class
	b[1] = cmd
	binary.LittleEndian.PutUint16(b[2:4], uint16(len(payload)))
	b[4] = seq
	binary.LittleEndian.PutUint32(b[5:9], uid)
	copy(b[9:], payload)
	return b
}

// NATProbe builds the 19-byte probe sent by CheckNATE to the help servers.
// ip must be the big-endian numeric form of the local address (the .so calls
// ToBigIP on the string form); port is the bound local UDP port. The second
// uint32 repeats the uid slot value observed at +9..12.
func NATProbe(seq uint8, uid uint32, ip uint32, port uint16) []byte {
	payload := make([]byte, 10)
	binary.LittleEndian.PutUint32(payload[0:4], uid)
	binary.BigEndian.PutUint32(payload[4:8], ip)
	binary.LittleEndian.PutUint16(payload[8:10], port)
	return BuildControlPacket(1, CmdNATProbe, seq, uid, payload)
}

// RelayPunch builds the relay request body produced by natPunch for
// newReqRelayMsg. Same 10-byte payload shape as NATProbe but with the
// external mapping (learned from earlier probe ACKs) in place of the local
// endpoint.
func RelayPunch(seq uint8, uid uint32, extIP uint32, extPort uint16) []byte {
	payload := make([]byte, 10)
	binary.LittleEndian.PutUint32(payload[0:4], uid)
	binary.BigEndian.PutUint32(payload[4:8], extIP)
	binary.LittleEndian.PutUint16(payload[8:10], extPort)
	return BuildControlPacket(1, CmdRelayPunch, seq, uid, payload)
}

// NATProbeACK decodes a 0x30 reply payload (TNATProbeMsg):
// {u32 uid; u32 ext_ip_be; u16 ext_port}. UID must match the sender's own.
func NATProbeACK(payload []byte, selfUID uint32) (ip uint32, port uint16, ok bool) {
	if len(payload) < 10 || binary.LittleEndian.Uint32(payload[0:4]) != selfUID {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(payload[4:8]), binary.LittleEndian.Uint16(payload[8:10]), true
}

// HeartbeatACK decodes a 0x27 reply payload (ACK_HEARTBEAT_INFO):
// {u32 ip_be; u16 port} - the server's view of our external endpoint.
func HeartbeatACK(payload []byte) (ip uint32, port uint16, ok bool) {
	if len(payload) < 6 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(payload[0:4]), binary.LittleEndian.Uint16(payload[4:6]), true
}

// PassiveConnectReq decodes a 0x13 server instruction payload
// (ReqCNatPunchStruct as filled by HandleClientData): an 8-byte ip:port pair
// at +0 followed by the port copy at +8.
func PassiveConnectReq(payload []byte) (ip uint32, port uint16, ok bool) {
	if len(payload) < 10 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(payload[0:4]), binary.LittleEndian.Uint16(payload[4:6]), true
}

// Classify inspects a received datagram and routes it like HandleClientData.
// Swordfish-class packets (negative first byte) are returned whole; control
// packets need the 9-byte header.
func Classify(b []byte) (class, cmd byte, payload []byte, ok bool) {
	if len(b) < 1 {
		return 0, 0, nil, false
	}
	class = b[0]
	if int8(class) < 0 {
		return class, 0, b, true // Swordfish stream, caller handles rev32
	}
	if class|2 != 3 || len(b) < 9 {
		return class, 0, nil, false
	}
	cmd = b[1]
	n := int(binary.LittleEndian.Uint16(b[2:4]))
	if 9+n > len(b) {
		n = len(b) - 9
	}
	return class, cmd, b[9 : 9+n], true
}
