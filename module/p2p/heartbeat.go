package p2p

import (
	"encoding/binary"
)

// Heartbeat command word recovered at KwMV.dll 0x100187c0.
const hbCommand = 0x000E2103

// Heartbeat is the 23-byte registration packet sent every 30 scheduler ticks
// to the HeartbeatServer list. The reply carries the client's external IP
// (NAT probe) and ACKs the session, after which tracker queries are answered.
//
// Exact wire layout (0x100187c0 + caller 0x100239d0):
//
//	+0  u32 LE 0x000E2103  command word
//	+4  u32 LE 0           always zero ([ebp-0xc] = bl = 0)
//	+8  u8                 first byte of the local IP (redundant copy)
//	+9  u32 LE             uid (g_login+0x7C)
//	+13 u32 LE             local IP (g_login+0x80)
//	+17 u32 LE             port | nat<<16 (g_login+0x84 / +0x86)
//	+21 u16 LE             proxy flag
type Heartbeat struct {
	Seq      uint8  // unused on wire; kept for reply parsing symmetry
	UID      uint32 // locally generated kid in [1e8, 2e8)
	IP       uint32 // external IP as reported by earlier replies
	Port     uint16 // local CSF UDP port
	NAT      uint16 // NAT type, initialized to 3
	ProxyFlg uint16
}

// Marshal renders the packet exactly as KwMV builds it. h.IP must be in
// big-endian numeric form (e.g. binary.BigEndian.Uint32 of a dotted quad),
// so LittleEndian stores emit the on-wire network byte order.
func (h Heartbeat) Marshal() []byte {
	b := make([]byte, 23)
	binary.LittleEndian.PutUint32(b[0:4], hbCommand)
	binary.LittleEndian.PutUint32(b[4:8], 0)
	b[8] = byte(h.IP >> 24)
	binary.LittleEndian.PutUint32(b[9:13], h.UID)
	binary.LittleEndian.PutUint32(b[13:17], h.IP)
	binary.LittleEndian.PutUint32(b[17:21], uint32(h.Port)|uint32(h.NAT)<<16)
	binary.LittleEndian.PutUint16(b[21:23], h.ProxyFlg)
	return b
}

// ParseHeartbeat decodes a reply if it carries the heartbeat command word.
func ParseHeartbeat(b []byte) (Heartbeat, bool) {
	if len(b) < 23 || binary.LittleEndian.Uint32(b[0:4]) != hbCommand {
		return Heartbeat{}, false
	}
	return Heartbeat{
		Seq:      b[8],
		UID:      binary.LittleEndian.Uint32(b[9:13]),
		IP:       binary.LittleEndian.Uint32(b[13:17]),
		Port:     binary.LittleEndian.Uint16(b[17:19]),
		NAT:      binary.LittleEndian.Uint16(b[19:21]),
		ProxyFlg: binary.LittleEndian.Uint16(b[21:23]),
	}, true
}

// DefaultHeartbeatServers mirrors the server-pushed "HeartbeatServer" config
// value from http://config.kuwo.cn/uc/s?m= ([p2p] section, see docs §10.60).
// The DLL built-in list (211.100.49.14 etc.) is dead; live servers as of
// 2026-08: 175.102.178.96/.97 (TCP 25607 verified reachable).
var DefaultHeartbeatServers = []string{
	"175.102.178.96:25607",
	"175.102.178.97:25607",
}
