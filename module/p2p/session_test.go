package p2p

import (
	"net"
	"sync"
	"testing"
	"time"
)

// loopbackPeer answers a CSF handshake as a tracker would, then echoes PSH.
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
	if h.Flags != FlagSYN {
		t.Errorf("want SYN got %02x", h.Flags)
		return
	}
	synack := Header{Seq: 100, Ack: h.Seq + 1, Flags: FlagSYN | FlagACK, Window: defaultWin}
	pc.WriteTo(synack.Marshal(), addr)
	// expect ACK
	n, _, err = pc.ReadFrom(buf)
	if err != nil {
		t.Errorf("peer read ACK: %v", err)
		return
	}
	h = ParseHeader(buf[:HeadLen])
	if h.Flags != FlagACK || h.Ack != 101 {
		t.Errorf("want ACK(101) got flags=%02x ack=%d", h.Flags, h.Ack)
		return
	}
	// expect PSH payload
	n, _, err = pc.ReadFrom(buf)
	if err != nil {
		t.Errorf("peer read PSH: %v", err)
		return
	}
	h = ParseHeader(buf[:HeadLen])
	if h.Flags&FlagPSH == 0 {
		t.Errorf("want PSH got %02x", h.Flags)
		return
	}
	payload := string(buf[HeadLen:n])
	// echo it back with a fresh seq
	echo := Header{Seq: 101, Ack: h.Seq + uint32(n-HeadLen) + 1, Flags: FlagPSH | FlagACK}.Marshal()
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
	s, err := Dial("", raddr)
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
			s, err := Dial("", pc.LocalAddr().(*net.UDPAddr))
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
