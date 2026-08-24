package p2p

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

// CSF session state machine over UDP, mirroring KwMV's dispatch table at
// 0x1001cc24: SYN(0x01) / ACK(0x02) / PSH(0x10) / RST(0x08).
//
// Handshake (three-way, cf. SYNACK handler 0x1001bce0 which answers with
// seq=peer.ack, ack=peer.seq+1):
//
//	client -> SYN(seq=n)
//	server -> SYN|ACK(seq=m, ack=n+1)
//	client -> ACK(seq=n+1, ack=m+1)

// sameHost compares the source address of an inbound datagram with the peer.
func sameHost(from net.Addr, raddr *net.UDPAddr) bool {
	ua, ok := from.(*net.UDPAddr)
	return ok && ua.IP.Equal(raddr.IP)
}

var (
	ErrTimeout     = errors.New("p2p: handshake timeout")
	ErrReset       = errors.New("p2p: connection reset by peer")
	ErrNotEstablished = errors.New("p2p: session not established")
)

const (
	defaultWin      = 0x80 // minimum advertised window observed in KwMV
	handshakeWait   = 3 * time.Second
	idleReadTimeout = 10 * time.Second
)

// Session is one CSF conversation with a tracker or peer node.
type Session struct {
	conn *net.UDPConn
	addr *net.UDPAddr

	mu       sync.Mutex
	localSeq uint32
	peerAck  uint32 // next byte offset the peer expects from us
	est      bool
	closed   bool
}

// Dial performs the three-way CSF handshake against addr.
func Dial(laddr string, raddr *net.UDPAddr) (*Session, error) {
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
	s := &Session{conn: uc, addr: raddr, localSeq: 1}

	// SYN
	if _, err := uc.WriteTo(s.syn(), raddr); err != nil {
		uc.Close()
		return nil, err
	}

	// SYN|ACK
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
		if h.Flags&FlagSYN == 0 || h.Flags&FlagACK == 0 {
			continue // stray packet; keep waiting for the SYNACK
		}
		s.mu.Lock()
		s.peerAck = h.Seq + 1
		s.est = true
		s.mu.Unlock()

		// ACK
		ack := Header{Seq: h.Ack, Ack: h.Seq + 1, Flags: FlagACK, Window: defaultWin}
		uc.WriteTo(ack.Marshal(), raddr)
		break
	}
	uc.SetReadDeadline(time.Time{})
	return s, nil
}

func (s *Session) syn() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Header{Seq: s.localSeq, Flags: FlagSYN, Window: defaultWin}.Marshal()
}

// Send transmits payload as a PSH packet.
func (s *Session) Send(payload []byte) error {
	s.mu.Lock()
	if !s.est || s.closed {
		s.mu.Unlock()
		return ErrNotEstablished
	}
	seq := s.localSeq
	pkt := Header{Seq: seq, Ack: s.peerAck, Flags: FlagPSH | FlagACK}.Marshal()
	s.localSeq += uint32(len(payload)) + 1
	s.mu.Unlock()
	pkt = append(pkt, payload...)
	_, err := s.conn.WriteTo(pkt, s.addr)
	return err
}

// Recv waits for one PSH data segment and returns its payload.
func (s *Session) Recv() ([]byte, error) {
	buf := make([]byte, 65535)
	s.conn.SetReadDeadline(time.Now().Add(idleReadTimeout))
	for {
		n, from, err := s.conn.ReadFrom(buf)
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
		if h.Flags&FlagRST != 0 {
			return nil, ErrReset
		}
		if h.Flags&FlagPSH == 0 {
			// bare ACK or keepalive: acknowledge nothing, keep waiting
			continue
		}
		payload := make([]byte, n-HeadLen)
		copy(payload, buf[HeadLen:n])
		binary.BigEndian.Uint32(buf[0:4]) // peer seq (kept for trace tooling)

		// piggyback ACK
		s.mu.Lock()
		s.peerAck = h.Seq + uint32(len(payload)) + 1
		myAck := s.peerAck
		mySeq := s.localSeq
		s.mu.Unlock()
		ackPkt := Header{Seq: mySeq, Ack: myAck, Flags: FlagACK, Window: defaultWin}.Marshal()
		s.conn.WriteTo(ackPkt, s.addr)
		return payload, nil
	}
}

// Close tears the session down with a RST.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	seq, ack := s.localSeq, s.peerAck
	s.mu.Unlock()
	rst := Header{Seq: seq, Ack: ack, Flags: FlagRST | FlagACK, Window: defaultWin}.Marshal()
	s.conn.WriteTo(rst, s.addr)
	return s.conn.Close()
}
