// kwmsg protocol (KwMusicDLL.dll UDP connected socket, port 7788)
//
// Frame: 116 bytes = 8B header (big-endian) + 108B payload (big-endian).
//
// Header (8B, big-endian):
//   +0: u16 type   = 1
//   +2: u16 sub    = 0
//   +4: u16 len    = 108
//   +6: u16 magic  = 0x4399
//
// Payload (108B, big-endian):
//   +0:  u32 mid        = 0
//   +4:  u32 kid        = game_mbox_id from login cookie
//   +8:  u32 combo      = 0x00010001
//   +12: u32 const_f    = 0x0000000f
//   +16: u32 try        = heartbeat retry count
//   +20: [24B] reserved = 0x00
//   +44: [32B] config_ver  = "kwmusic_web_1_bds_20171206.exe\0\0"
//   +76: [16B] client_ver = "Win 6.2.9200\0\0\0\0"
//   +92: [16B] client_id  = "PC\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
//
// Captured: 6 identical frames sent ~60s apart to 39.156.121.20:7788.
// Server responds with NOTHING (no reply, no RST).
// Source: assets/1111_new.pcapng frames 11543,11957,12165,13123,44642,83962

package p2p

import (
	"encoding/binary"
	"fmt"
)

// KwmsgHdr is the 8-byte big-endian frame header.
type KwmsgHdr struct {
	Type    uint16 // 1
	Subtype uint16 // 0
	Len     uint16 // 108
	Magic   uint16 // 0x4399
}

func (h *KwmsgHdr) Marshal() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], h.Type)
	binary.BigEndian.PutUint16(b[2:4], h.Subtype)
	binary.BigEndian.PutUint16(b[4:6], h.Len)
	binary.BigEndian.PutUint16(b[6:8], h.Magic)
	return b
}

func UnmarshalKwmsgHdr(b []byte) (*KwmsgHdr, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("kwmsg: short header %dB", len(b))
	}
	magic := binary.BigEndian.Uint16(b[6:8])
	if magic != 0x4399 {
		return nil, fmt.Errorf("kwmsg: bad magic 0x%04x", magic)
	}
	return &KwmsgHdr{
		Type:    binary.BigEndian.Uint16(b[0:2]),
		Subtype: binary.BigEndian.Uint16(b[2:4]),
		Len:     binary.BigEndian.Uint16(b[4:6]),
		Magic:   magic,
	}, nil
}

// KwmsgPayload is the 108-byte big-endian heartbeat payload.
// Layout verified from live capture (assets/1111_new.pcapng):
//
//	+0:  u32 mid        (0)
//	+4:  u32 kid        (game_mbox_id)
//	+8:  u32 combo      (0x00010001)
//	+12: u32 const_f    (0x0000000f)
//	+16: u32 try        (retry count, e.g. 21613533)
//	+20: [24B] reserved (= 0)
//	+44: [32B] config_ver  ("kwmusic_web_1_bds_20171206.exe\0\0")
//	+76: [16B] client_ver = ("Win 6.2.9200\0\0\0\0")
//	+92: [16B] client_id  = ("PC\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
type KwmsgPayload struct {
	MID       uint32  // 0
	KID       uint32  // game_mbox_id from login
	Combo     uint32  // 0x00010001
	ConstF    uint32  // 0x0000000f
	Try       uint32  // retry count
	Reserved  [24]byte
	ConfigVer [32]byte
	ClientVer [16]byte
	ClientID  [16]byte
}

func (p *KwmsgPayload) Marshal() []byte {
	b := make([]byte, 108)
	binary.BigEndian.PutUint32(b[0:4], p.MID)
	binary.BigEndian.PutUint32(b[4:8], p.KID)
	binary.BigEndian.PutUint32(b[8:12], p.Combo)
	binary.BigEndian.PutUint32(b[12:16], p.ConstF)
	binary.BigEndian.PutUint32(b[16:20], p.Try)
	copy(b[20:44], p.Reserved[:])
	copy(b[44:76], p.ConfigVer[:])
	copy(b[76:92], p.ClientVer[:])
	copy(b[92:108], p.ClientID[:])
	return b
}

// UnmarshalKwmsgFrame parses a 116B kwmsg frame into header + payload.
func UnmarshalKwmsgFrame(b []byte) (*KwmsgHdr, *KwmsgPayload, error) {
	if len(b) < 116 {
		return nil, nil, fmt.Errorf("kwmsg: short frame %dB", len(b))
	}
	hdr, err := UnmarshalKwmsgHdr(b)
	if err != nil {
		return nil, nil, err
	}
	var p KwmsgPayload
	p.MID = binary.BigEndian.Uint32(b[8:12])
	p.KID = binary.BigEndian.Uint32(b[12:16])
	p.Combo = binary.BigEndian.Uint32(b[16:20])
	p.ConstF = binary.BigEndian.Uint32(b[20:24])
	p.Try = binary.BigEndian.Uint32(b[24:28])
	copy(p.Reserved[:], b[28:52])
	copy(p.ConfigVer[:], b[52:84])
	copy(p.ClientVer[:], b[84:100])
	copy(p.ClientID[:], b[100:116])
	return hdr, &p, nil
}

// BuildKwmsgHeartbeat constructs a 116B kwmsg heartbeat frame.
func BuildKwmsgHeartbeat(kid uint32, try uint32, configVer, clientVer string) []byte {
	p := KwmsgPayload{
		MID:    0,
		KID:    kid,
		Combo:  0x00010001,
		ConstF: 0x0000000f,
		Try:    try,
	}
	copy(p.ConfigVer[:], configVer)
	copy(p.ClientVer[:], clientVer)
	copy(p.ClientID[:], "PC")
	hdr := KwmsgHdr{Type: 1, Subtype: 0, Len: 108, Magic: 0x4399}
	return append(hdr.Marshal(), p.Marshal()...)
}

// KwmsgServers are the kwmsg message servers observed in live captures.
var KwmsgServers = []string{
	"39.156.121.20:7788",
	"39.156.121.65:7788",
	"39.156.123.32:7788",
}

// DefaultConfigVer and DefaultClientVer from the live capture.
const DefaultConfigVer = "kwmusic_web_1_bds_20171206.exe"
const DefaultClientVer = "Win 6.2.9200"

// CapturedFrameHex is the exact raw hex of a captured heartbeat frame (116B).
const CapturedFrameHex = "00010000006c43990000000000e91e56000100010000000f0149cbdd0000000000000000000000000000000000000000000000006b776d757369635f7765625f315f6264735f32303137313230362e657865000057696e20362e322e393230300000000050430000000000000000000000000000"