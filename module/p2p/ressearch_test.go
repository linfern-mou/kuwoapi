package p2p

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func TestBuildPCUQRY(t *testing.T) {
	got := BuildPCUQRY(PCQueryParams{
		Sig1: 2872976053, Sig2: 860573832, UID: 15277654,
		NAT: 3, LocalIP: "192.168.1.8", RidOverride: "228720849",
	})
	want := "<001><U_QRY>|<2872976053,860573832>|<15277654><><>|<192.168.1.8>|" +
		"<228720849>|<uip:192.168.1.8>|<new>|<nat:3>|<flags:0><speer>|<ipdeny:no>|<loginid:>\r\n"
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}

// The literal <rid> slot is what the original client sends: resource lookup
// is keyed by the sig pair alone.
func TestBuildPCUQRYLiteralRid(t *testing.T) {
	got := BuildPCUQRY(PCQueryParams{
		Sig1: 640604884, Sig2: 960750357, UID: 15277654,
		NAT: 3, LocalIP: "192.168.1.7",
	})
	want := "<001><U_QRY>|<640604884,960750357>|<15277654><><>|<192.168.1.7>|" +
		"<rid>|<uip:192.168.1.7>|<new>|<nat:3>|<flags:0><speer>|<ipdeny:no>|<loginid:>\r\n"
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestDecodeResBodyBase64(t *testing.T) {
	raw := []byte{0x62, 0x52, 0x0e, 0x62, 0x11}
	body := []byte(base64.StdEncoding.EncodeToString(raw))
	out, err := DecodeResBody([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"), body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, raw) {
		t.Fatalf("got % x want % x", out, raw)
	}
}

func TestDecodeResBodyZlib(t *testing.T) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write([]byte("FormatVer:1.1|PEERS:(1,2.3.4.5,6000,0,0,0,1)"))
	zw.Close()
	payload := buf.Bytes()

	body := make([]byte, 8+len(payload))
	binary.LittleEndian.PutUint32(body[0:4], 44)
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(payload)))
	copy(body[8:], payload)

	hdr := []byte("HTTP/1.1 200 OK\r\nContent-Encoding: zlib\r\n\r\n")
	out, err := DecodeResBody(hdr, body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("FormatVer:1.1")) {
		t.Fatalf("inflate mismatch: %q", out)
	}
}

func TestParseSearchServers(t *testing.T) {
	ini := "[ResSearch]\r\nResServCnt=2\r\n" +
		"SearchServer7=664566069\r\n" + // 0x279C7935 -> 39.156.121.53 big-endian
		"SearchServer8=664566562\r\n" + // 0x279C7B22 -> 39.156.123.34
		"SearchServerDNS=http://43.144.129.208\r\n"
	got := ParseSearchServers(ini)
	if len(got) != 2 || got[0] != "39.156.121.53" || got[1] != "39.156.123.34" {
		t.Fatalf("got %v", got)
	}
}
