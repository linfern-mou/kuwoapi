package p2p

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"
)

// Swordfish session over UDP, mirroring libp2p.so Swordfish::connect /
// recvSYNACKE / onRecvPacket (docs §10.63).
//
// Handshake:
//
//	client -> SYN   {seq=isn, ver=0x8C, flags=0x02, win} + {ver=1, uid}
//	server -> SYNACK{seq=srvISN, flags=0x12} + payload (srvISN also at payload+4)
//	client -> ACK   reuse: {seq=srvISN, ack=srvISN+1, flags=0x12} + echoed payload

var (
	ErrTimeout        = errors.New("p2p: handshake timeout")
	ErrReset          = errors.New("p2p: connection reset by peer")
	ErrNotEstablished = errors.New("p2p: session not established")
)

const (
	defaultWin      = 0x80
	handshakeWait   = 3 * time.Second
	idleReadTimeout = 10 * time.Second
)

func sameHost(from net.Addr, raddr *net.UDPAddr) bool {
	ua, ok := from.(*net.UDPAddr)
	return ok && ua.IP.Equal(raddr.IP)
}

// Session is one Swordfish conversation with a tracker or peer node.
type Session struct {
	conn *net.UDPAddr
	addr *net.UDPAddr
	sock *net.UDPConn

	mu       sync.Mutex
	localSeq uint32 // next packet number we send
	peerSeq  uint32 // last packet number seen from the peer
	srvTrl   []byte // SYNACK payload echo required by the ACK step
	est      bool
	closed   bool
}

// Dial performs the three-way handshake against addr.
func Dial(laddr string, raddr *net.UDPAddr, uid uint32) (*Session, error) {
	var la *net.UDPAddr
	if laddr != "" {
		var err error
		if la, err = net.ResolveUDPAddr("udp", laddr); err != nil {
			return nil, err
		}
	} else {
		la = &net.UDPAddr{Port: 0}
	}
	uc, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}
	isn := rand.Uint32()
	s := &Session{sock: uc, addr: raddr, localSeq: isn}

	if _, err := uc.WriteTo(SYN(isn, uid, defaultWin), raddr); err != nil {
		uc.Close()
		return nil, err
	}

	buf := make([]byte, 1500)
	uc.SetReadDeadline(time.Now().Add(handshakeWait))
	for {
		n, from, err := uc.ReadFrom(buf)
		if err != nil {
			uc.Close()
			return nil, ErrTimeout
		}
		if !sameHost(from, raddr) || n < HeadLen {
			continue
		}
		h := ParseHeader(buf[:HeadLen])
		if h.Type() != 2 {
			continue // not a SYNACK; keep waiting
		}
		s.mu.Lock()
		s.peerSeq = h.Seq
		trl := make([]byte, n-HeadLen)
		copy(trl, buf[HeadLen:n])
		s.srvTrl = trl
		s.est = true
		s.mu.Unlock()

		// third step: packACKE reuses the inbound packet - seq stays at the
		// server's ISN and ack = server ISN + 1, original payload echoed.
		uc.WriteTo(AckOnly(h.Seq, defaultWin, trl), raddr)
		break
	}
	uc.SetReadDeadline(time.Time{})
	return s, nil
}

// Send transmits one data packet; sequence advances per packet.
func (s *Session) Send(payload []byte) error {
	s.mu.Lock()
	if !s.est || s.closed {
		s.mu.Unlock()
		return ErrNotEstablished
	}
	seq := s.localSeq
	ack := s.peerSeq + 1
	s.localSeq++
	s.mu.Unlock()
	pkt := Data(seq, ack, payload, defaultWin)
	_, err := s.sock.WriteTo(pkt, s.addr)
	return err
}

// Recv waits for one data segment and returns its payload.
func (s *Session) Recv() ([]byte, error) {
	buf := make([]byte, 65535)
	s.sock.SetReadDeadline(time.Now().Add(idleReadTimeout))
	for {
		n, from, err := s.sock.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil, ErrTimeout
			}
			return nil, err
		}
		if !sameHost(from, s.addr) || n < HeadLen {
			continue
		}
		h := ParseHeader(buf[:HeadLen])
		t := h.Type()
		switch t {
		case 9:
			return nil, ErrReset
		case 3, 0:
			payload := make([]byte, n-HeadLen)
			copy(payload, buf[HeadLen:n])
			s.mu.Lock()
			s.peerSeq = h.Seq
			mySeq := s.localSeq
			s.mu.Unlock()
			ackPkt := Header{Seq: mySeq, Ack: h.Seq + 1, Flags: FlagACK, Window: defaultWin}.Marshal()
			s.sock.WriteTo(ackPkt, s.addr)
			return payload, nil
		default:
			continue
		}
	}
}

// LocalPort returns the local UDP port bound for this session.
func (s *Session) LocalPort() int {
	return s.sock.LocalAddr().(*net.UDPAddr).Port
}

// PeerSeq reports the latest sequence number seen from the peer.
func (s *Session) PeerSeq() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerSeq
}

// Close tears the session down with a FIN.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	seq, ack := s.localSeq, s.peerSeq+1
	s.mu.Unlock()
	fin := Header{Seq: seq, Ack: ack, Flags: FlagFIN | FlagACK, Window: defaultWin}.Marshal()
	s.sock.WriteTo(fin, s.addr)
	return s.sock.Close()
}

var _ = binary.LittleEndian
