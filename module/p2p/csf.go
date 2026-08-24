// Package p2p implements the KwMV.dll P2P download protocol recovered by
// static reverse engineering. See .monkeycode/docs/p2p-reverse-analysis.md
// sections 10.x for the evidence behind every constant and layout.
package p2p

import (
	"encoding/binary"
)

// Wire header (12 bytes) preceding every CSF payload.
//
//	+0x00 u32 seq      (big-endian on wire)
//	+0x04 u32 ack
//	+0x08 u8  headLen  (always 0x0C)
//	+0x09 u8  flags
//	+0x0A u16 window   (little-endian)
const (
	HeadLen = 0x0C
)

// Flag bits for the CSF header flags byte.
const (
	FlagSYN = 0x01
	FlagACK = 0x02
	FlagRST = 0x08
	FlagPSH = 0x10
)

// Header is the parsed form of the 12-byte CSF wire header.
type Header struct {
	Seq     uint32
	Ack     uint32
	Flags   uint8
	Window  uint16
}

// Marshal renders the header onto the wire.
func (h Header) Marshal() []byte {
	b := make([]byte, HeadLen)
	binary.BigEndian.PutUint32(b[0:4], h.Seq)
	binary.BigEndian.PutUint32(b[4:8], h.Ack)
	b[8] = HeadLen
	b[9] = h.Flags
	binary.LittleEndian.PutUint16(b[10:12], h.Window)
	return b
}

// ParseHeader decodes a CSF wire header.
func ParseHeader(b []byte) Header {
	return Header{
		Seq:    binary.BigEndian.Uint32(b[0:4]),
		Ack:    binary.BigEndian.Uint32(b[4:8]),
		Flags:  b[9],
		Window: binary.LittleEndian.Uint16(b[10:12]),
	}
}

// SYN builds a connection-opening packet. Window is the receive capacity the
// client advertises (KwMV uses remaining-buffer size, minimum observed 0x80).
func SYN(seq uint32, window uint16) []byte {
	return Header{Seq: seq, Flags: FlagSYN, Window: window}.Marshal()
}

// PSH builds a data-carrying packet wrapping an already serialized payload
// such as the U_QRY request text.
func PSH(seq, ack uint32, payload []byte) []byte {
	h := Header{Seq: seq, Ack: ack, Flags: FlagPSH | FlagACK}.Marshal()
	return append(h, payload...)
}
