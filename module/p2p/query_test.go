package p2p

import (
	"testing"
)

func TestHeaderMarshal(t *testing.T) {
	h := Header{Seq: 1, Ack: 0, Flags: FlagSYN, Window: 0x80}
	b := h.Marshal()
	if len(b) != HeadLen {
		t.Fatalf("len=%d", len(b))
	}
	want := []byte{0, 0, 0, 1, 0, 0, 0, 0, 0x0C, 0x01, 0x80, 0x00}
	for i := range want {
		if b[i] != want[i] {
			t.Fatalf("byte %d = %02x want %02x", i, b[i], want[i])
		}
	}
}

func TestHeartbeatMarshal(t *testing.T) {
	hb := Heartbeat{Seq: 1, UID: 123434546, IP: 0, Port: 12345, NAT: 3}
	b := hb.Marshal()
	// 23-byte layout per 0x100187c0
	if len(b) != 23 {
		t.Fatalf("len=%d", len(b))
	}
	p, ok := ParseHeartbeat(b)
	if !ok || p.UID != hb.UID || p.Port != hb.Port || p.NAT != hb.NAT {
		t.Fatalf("roundtrip failed: %+v ok=%v", p, ok)
	}
}

func TestParseResponsePeers(t *testing.T) {
	sample := "FormatVer:1.1|sig:(2608621834,2438534005)|searchtm:47|PEERS:" +
		"(100,\"27.18.39.80\",25607,1,2,3,7)" +
		"(200,192.168.1.2,6000,0,0,0,9)" +
		"FILE_LEN<4234567><URL>http://a/x.mp3<URL>http://b/y.mp3<"
	r := ParseResponse(sample)
	if r.Denied || r.ResourceDel {
		t.Fatal("unexpected flags")
	}
	if r.FileLen != 4234567 {
		t.Fatalf("filelen=%d", r.FileLen)
	}
	if len(r.URLs) != 2 || r.URLs[0] != "http://a/x.mp3" {
		t.Fatalf("urls=%v", r.URLs)
	}
	if len(r.Peers) != 2 || r.Peers[0].IP != "\"27.18.39.80\"" && r.Peers[0].IP != "27.18.39.80" {
		t.Fatalf("peers=%+v", r.Peers)
	}
}

func TestParseResponseDenied(t *testing.T) {
	r := ParseResponse("<DENY_IP>xxx")
	if !r.Denied {
		t.Fatal("want denied")
	}
	r2 := ParseResponse("...<RES_DEL>...")
	if !r2.ResourceDel {
		t.Fatal("want resdel")
	}
}
