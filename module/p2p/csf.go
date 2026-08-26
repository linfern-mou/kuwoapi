package p2p

import (
	"encoding/binary"
)

// Swordfish wire protocol recovered from libp2p.so Packet methods
// (ctor 0xcd974, packSYN 0xcd9d4, packACKE 0xcda34, getType 0xcdb74,
// Swordfish::connect 0xd7978, recvSYNACKE 0xd8b10) - docs §10.63.
//
// Every CSF datagram is a 12-byte little-endian header plus payload:
//
//	+0x00 u32 seq   local packet number (SYN carries the ISN)
//	+0x04 u32 ack   peer packet number being acknowledged
//	+0x08 u8  ver   (prev&0xF0)|0x0C - fresh packets use 0x8C
//	+0x09 u8  flags bit0 FIN, bit1 SYN, bit3 RST, bit4 hasACK
//	+0x0A u16 win   receive window
//
// Sequence numbers advance by one per packet (SACK bitmap indexing in
// recvACKE walks packets, not bytes).
const (
	HeadLen = 12
)

// Flag bits for the flags byte at offset 9.
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x08
	FlagACK = 0x10 // "packet carries a valid ack number"
	VerByte = 0x8C
)

// Header is the parsed form of the 12-byte Swordfish header.
type Header struct {
	Seq    uint32
	Ack    uint32
	Flags  uint8
	Window uint16
}

// Marshal renders the header onto the wire.
func (h Header) Marshal() []byte {
	b := make([]byte, HeadLen)
	binary.LittleEndian.PutUint32(b[0:4], h.Seq)
	binary.LittleEndian.PutUint32(b[4:8], h.Ack)
	b[8] = VerByte
	b[9] = h.Flags
	binary.LittleEndian.PutUint16(b[10:12], h.Window)
	return b
}

// ParseHeader decodes a Swordfish wire header.
func ParseHeader(b []byte) Header {
	return Header{
		Seq:    binary.LittleEndian.Uint32(b[0:4]),
		Ack:    binary.LittleEndian.Uint32(b[4:8]),
		Flags:  b[9],
		Window: binary.LittleEndian.Uint16(b[10:12]),
	}
}

// Type mirrors Packet::getType: 1/2 SYN/SYNACK, 3 data, 4/5 FIN/FINACK,
// 9 reset, 0 data-with-ack.
func (h Header) Type() int {
	f := h.Flags
	switch {
	case f&FlagRST != 0:
		return 9
	case f&FlagSYN != 0:
		t := 1
		if f&FlagACK != 0 {
			t = 2
		}
		return t
	case f&FlagFIN != 0:
		t := 4
		if f&FlagACK != 0 {
			t = 5
		}
		return t
	case f&FlagACK != 0:
		return 0
	default:
		return 3
	}
}

// SYN builds the 20-byte connection request from Swordfish::connect:
// payload {u32 proto_version=1, u32 uid}.
func SYN(isn uint32, uid uint32, window uint16) []byte {
	b := Header{Seq: isn, Flags: FlagSYN, Window: window}.Marshal()
	b = append(b, make([]byte, 8)...)
	binary.LittleEndian.PutUint32(b[12:16], 1)
	binary.LittleEndian.PutUint32(b[16:20], uid)
	return b
}

// Data builds a data-carrying packet with piggybacked ack.
func Data(seq, ack uint32, payload []byte, window uint16) []byte {
	h := Header{Seq: seq, Ack: ack, Flags: FlagACK, Window: window}.Marshal()
	return append(h, payload...)
}

// AckOnly builds a bare acknowledgement mirroring recvSYNACKE's packACKE
// reuse of the inbound packet: seq keeps the peer's number, ack = peer+1.
func AckOnly(peerSeq uint32, window uint16, trailer []byte) []byte {
	b := Header{Seq: peerSeq, Ack: peerSeq + 1, Flags: FlagSYN | FlagACK, Window: window}.Marshal()
	return append(b, trailer...)
}
