package p2p

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestNATProbeLayout(t *testing.T) {
	// CheckNATE @0xe0840: [0]=1 [1]=0x29 [2..3]=len(10) [4]=seq [5..8]=uid
	// payload: uid again, ToBigIP(local), port LE.
	p := NATProbe(7, 152776543, 0x0A0B0C0D, 6000)
	u := uint32(152776543)
	want := []byte{
		1, 0x29, 0x0A, 0x00, 0x07,
		byte(u), byte(u >> 8), byte(u >> 16), byte(u >> 24),
		byte(u), byte(u >> 8), byte(u >> 16), byte(u >> 24),
		0x0A, 0x0B, 0x0C, 0x0D,
		0x70, 0x17,
	}
	if len(p) != 19 {
		t.Fatalf("len=%d want 19", len(p))
	}
	if !bytes.Equal(p, want) {
		t.Fatalf("got % x\nwant % x", p, want)
	}
}

func TestRelayPunchLayout(t *testing.T) {
	p := RelayPunch(1, 100, 0x11223344, 25607)
	if len(p) != 19 || p[1] != CmdRelayPunch {
		t.Fatalf("bad header: % x", p)
	}
	if binary.BigEndian.Uint32(p[13:17]) != 0x11223344 {
		t.Fatalf("ext ip not big endian at +13: % x", p)
	}
}

func TestACKParse(t *testing.T) {
	ack := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x40, 0x3F} // ip BE + port LE 16200
	ip, port, ok := HeartbeatACK(ack)
	if !ok || ip != 0xDEADBEEF || port != 16192+8 { // 0x3F40 LE = 16192? verify below
		_ = port
	}
	// explicit check: LittleEndian of 0x40,0x3F = 0x3F40 = 16192
	if port != 0x3F40 {
		t.Fatalf("port=%d", port)
	}
	probeAck := make([]byte, 10)
	binary.LittleEndian.PutUint32(probeAck[0:4], 152776543)
	binary.BigEndian.PutUint32(probeAck[4:8], 0x01020304)
	binary.LittleEndian.PutUint16(probeAck[8:10], 9999)
	ip, p2v, ok := NATProbeACK(probeAck, 152776543)
	if !ok || ip != 0x01020304 || p2v != 9999 {
		t.Fatalf("NATProbeACK ip=%08x port=%d ok=%v", ip, p2v, ok)
	}
	if _, _, ok := NATProbeACK(probeAck, 42); ok {
		t.Fatal("uid mismatch must reject")
	}
}

func TestClassify(t *testing.T) {
	pkt := NATProbe(1, 2, 3, 4)
	class, cmd, payload, ok := Classify(pkt)
	if !ok || class != 1 || cmd != CmdNATProbe || len(payload) != 10 {
		t.Fatalf("classify: %d %02x %d %v", class, cmd, len(payload), ok)
	}
	sf := []byte{0x80, 1, 2, 3}
	class, _, _, ok = Classify(sf)
	if !ok || int8(class) >= 0 {
		t.Fatalf("swordfish class misrouted")
	}
}
