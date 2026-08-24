package p2p

import (
	"encoding/binary"
)

// Heartbeat command word recovered at KwMV.dll 0x100187c0.
const hbCommand = 0x000E2103

// Heartbeat is the 23-byte registration packet sent every 30 scheduler ticks
// to the HeartbeatServer list. The reply carries the client's external IP
// (NAT probe) and ACKs the session, after which tracker queries are answered.
type Heartbeat struct {
	Seq      uint8  // tick counter byte (g_login+0xC8)
	UID      uint32 // locally generated kid in [1e8, 2e8)
	IP       uint32 // external IP as reported by earlier replies
	Port     uint16 // local CSF UDP port
	NAT      uint16 // NAT type, initialized to 3
	ProxyFlg uint16
}

// Marshal renders the packet exactly as KwMV builds it (little-endian fields).
func (h Heartbeat) Marshal() []byte {
	b := make([]byte, 23)
	binary.LittleEndian.PutUint32(b[0:4], hbCommand)
	b[4] = h.Seq
	binary.LittleEndian.PutUint32(b[5:9], h.UID)
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
		Seq:     b[4],
		UID:     binary.LittleEndian.Uint32(b[5:9]),
		IP:      binary.LittleEndian.Uint32(b[13:17]),
		Port:    binary.LittleEndian.Uint16(b[17:19]),
		NAT:     binary.LittleEndian.Uint16(b[19:21]),
		ProxyFlg: binary.LittleEndian.Uint16(b[21:23]),
	}, true
}

// DefaultHeartbeatServers mirrors the built-in "HeartbeatServer" config value:
// host:port entries joined by commas (KwMV.dll .rdata @0x1004a638 area).
var DefaultHeartbeatServers = []string{
	"211.100.49.14:25607",
	"60.29.226.173:25607",
	"60.28.205.36:25607",
}
