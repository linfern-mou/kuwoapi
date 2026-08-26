package p2p

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// loopbackPeer answers a Swordfish handshake as a tracker would, then echoes
// one data packet.
func loopbackPeer(t *testing.T, pc *net.UDPConn, done chan struct{}) {
	defer close(done)
	buf := make([]byte, 2048)
	// expect SYN
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Errorf("peer read SYN: %v", err)
		return
	}
	h := ParseHeader(buf[:HeadLen])
	if h.Flags != FlagSYN || h.Type() != 1 {
		t.Errorf("want SYN got flags=%02x type=%d", h.Flags, h.Type())
		return
	}
	if binary.LittleEndian.Uint32(buf[12:16]) != 1 {
		t.Errorf("SYN payload ver != 1: % x", buf[12:n])
	}
	const srvISN = uint32(100)
	synack := Header{Seq: srvISN, Flags: FlagSYN | FlagACK, Window: defaultWin}
	pkt := synack.Marshal()
	trailer := make([]byte, 8) // {u32 ?, u32 srvISN} shape per recvSYNACKE
	binary.LittleEndian.PutUint32(trailer[4:8], srvISN)
	pkt = append(pkt, trailer...)
	pc.WriteTo(pkt, addr)
	// expect ACK reusing our ISN
	n, _, err = pc.ReadFrom(buf)
	if err != nil {
		t.Errorf("peer read ACK: %v", err)
		return
	}
	h = ParseHeader(buf[:HeadLen])
	if h.Seq != srvISN || h.Ack != srvISN+1 || h.Type() != 2 {
		t.Errorf("want ACK reuse(seq=%d ack=%d type=2) got seq=%d ack=%d type=%d",
			srvISN, srvISN+1, h.Seq, h.Ack, h.Type())
		return
	}
	// expect data packet
	n, _, err = pc.ReadFrom(buf)
	if err != nil {
		t.Errorf("peer read data: %v", err)
		return
	}
	h = ParseHeader(buf[:HeadLen])
	payload := string(buf[HeadLen:n])
	// echo it back as a bare data packet (type 3)
	echo := Header{Seq: srvISN + 1, Window: defaultWin}.Marshal()
	echo = append(echo, []byte("resp:"+payload)...)
	pc.WriteTo(echo, addr)
}

func TestSessionHandshakeAndEcho(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	done := make(chan struct{})
	go loopbackPeer(t, pc, done)

	raddr := pc.LocalAddr().(*net.UDPAddr)
	s, err := Dial("", raddr, 152776543)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer s.Close()

	if err := s.Send([]byte("hello")); err != nil {
		t.Fatalf("send: %v", err)
	}
	resp, err := s.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if string(resp) != "resp:hello" {
		t.Fatalf("got %q", resp)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("peer goroutine hung")
	}
}

func TestConcurrentSessions(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pc, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
			defer pc.Close()
			done := make(chan struct{})
			go loopbackPeer(t, pc, done)
			s, err := Dial("", pc.LocalAddr().(*net.UDPAddr), 152776543)
			if err != nil {
				t.Errorf("dial: %v", err)
				return
			}
			s.Send([]byte("ping"))
			if _, err := s.Recv(); err != nil {
				t.Errorf("recv: %v", err)
			}
			s.Close()
			<-done
		}()
	}
	wg.Wait()
}
