// Command p2pcheck runs the recovered KwMV P2P handshake against the live
// tracker so the chain can be verified on a network with unrestricted UDP
// (the dev sandbox drops outbound UDP entirely).
//
// Usage:
//
//	go run ./cmd/p2pcheck <sig1> <sig2>
//
// e.g. sig pair for MUSIC_169753: 3264614461 1651339078
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"kuwoapi/module/p2p"
)

// public DNS used because Android lacks /etc/resolv.conf
const dnsServer = "8.8.8.8:53"

func main() {
	sig1, sig2 := uint32(3264614461), uint32(1651339078)
	if len(os.Args) >= 3 {
		a, _ := strconv.ParseUint(os.Args[1], 10, 32)
		b, _ := strconv.ParseUint(os.Args[2], 10, 32)
		sig1, sig2 = uint32(a), uint32(b)
	}
	// anonymous uid per KwMV.dll 0x10012b21: (FNV1a(machine) mod 1e8) + 1e8
	uid := uint32(152776543)

	fmt.Println("== stage 0: UDP egress sanity (standard DNS over UDP) ==")
	stage0OK := false
	for _, dns := range []string{"223.5.5.5:53", "8.8.8.8:53"} {
		dc, err := net.DialTimeout("udp", dns, 3*time.Second)
		if err != nil {
			fmt.Printf("  %s dial: %v\n", dns, err)
			continue
		}
		// standard query: A record for www.kuwo.cn
		q := []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			3, 'w', 'w', 'w', 4, 'k', 'u', 'w', 'o', 2, 'c', 'n', 0,
			0x00, 0x01, 0x00, 0x01,
		}
		dc.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
		if _, err := dc.Write(q); err != nil {
			fmt.Printf("  %s write: %v\n", dns, err)
		} else {
			buf := make([]byte, 512)
			if n, err := dc.Read(buf); err != nil {
				fmt.Printf("  %s: NO REPLY (%v) -> UDP egress blocked/filtered\n", dns, err)
			} else {
				stage0OK = true
				fmt.Printf("  %s: DNS reply %dB -> UDP egress OK\n", dns, n)
			}
		}
		dc.Close()
	}

	fmt.Println("\n== stage 1: heartbeat registration ==")
	hbAddr := &net.UDPAddr{IP: net.ParseIP("211.100.49.14"), Port: 25607}
	trkAddr := &net.UDPAddr{IP: net.ParseIP("175.102.178.96"), Port: 25607} // act.log fallback
	// Android has no /etc/resolv.conf so Go's resolver defaults to [::1]:53 and
	// fails; query a public DNS explicitly instead.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := resolver.LookupNetIP(ctx, "ip4", "deliver.kuwo.cn")
	if err == nil && len(ips) > 0 {
		trkAddr = &net.UDPAddr{IP: net.IP(ips[0].AsSlice()), Port: 25607}
		fmt.Println("tracker resolves to", trkAddr)
	}

	uc, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		fmt.Println("bind:", err)
		return
	}
	defer uc.Close()

	// outbound IP for the heartbeat packet (g_login+0x80 equivalent)
	conn, err := net.DialTimeout("udp", dnsServer, 3*time.Second)
	if err != nil {
		fmt.Println("local ip probe:", err)
		return
	}
	localIP := net.ParseIP(conn.LocalAddr().(*net.UDPAddr).IP.String()).To4()
	conn.Close()

	for i := 0; i < 5; i++ {
		hb := p2p.Heartbeat{UID: uid, NAT: 3, Port: uint16(uc.LocalAddr().(*net.UDPAddr).Port), IP: binary.BigEndian.Uint32(localIP)}
		pkt := hb.Marshal()
		uc.WriteTo(pkt, hbAddr)
		uc.WriteTo(pkt, trkAddr)
		fmt.Printf("heartbeat #%d -> %v / %v\n", i, hbAddr, trkAddr)
		buf := make([]byte, 2048)
		uc.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		if n, from, err := uc.ReadFrom(buf); err == nil {
			fmt.Printf("REPLY from %v (%dB): %s\n", from, n, hex.Dump(buf[:n]))
		}
		time.Sleep(300 * time.Millisecond)
	}

	fmt.Println("\n== stage 2: CSF session + U_QRY (3 attempts) ==")
	var sess *p2p.Session
	for attempt := 1; attempt <= 3; attempt++ {
		s, err := p2p.Dial("", trkAddr)
		if err == nil {
			sess = s
			fmt.Printf("handshake OK on attempt %d (lport=%d)\n", attempt, s.LocalPort())
			break
		}
		fmt.Printf("attempt %d: %v\n", attempt, err)
		time.Sleep(500 * time.Millisecond)
	}
	if sess == nil {
		if stage0OK {
			fmt.Println("(all 3 attempts no SYNACK while DNS-over-UDP works -> server ignores our SYN or port 25607/udp is specifically filtered)")
		} else {
			fmt.Println("(no SYNACK and even DNS over UDP fails -> carrier blocks UDP egress)")
		}
		return
	}
	defer sess.Close()

	req := p2p.BuildUQRY(p2p.QueryParams{
		UID:     uid,
		Sig1:    sig1,
		Sig2:    sig2,
		NAT:     3,
		LocalIP: "0.0.0.0",
		IPDeny:  "no",
	})
	fmt.Printf("U_QRY text:\n%s\n", req)
	if err := sess.Send([]byte(req)); err != nil {
		fmt.Println("send:", err)
		return
	}
	resp, err := sess.Recv()
	if err != nil {
		fmt.Println("recv:", err)
		return
	}
	fmt.Printf("response (%dB):\n%s\n", len(resp), resp)

	r := p2p.ParseResponse(string(resp))
	switch {
	case r.Denied:
		fmt.Println("result: DENY_IP")
	case r.ResourceDel:
		fmt.Println("result: RES_DEL")
	default:
		fmt.Printf("result: ver=%s searchtm=%d filelen=%d peers=%d urls=%d\n",
			r.FormatVer, r.SearchTM, r.FileLen, len(r.Peers), len(r.URLs))
		for _, u := range r.URLs {
			fmt.Println("  URL:", u)
		}
		for _, p := range r.Peers {
			fmt.Printf("  PEER kid=%d %s:%d flags=%d,%d,%d idx=%d\n",
				p.Kid, p.IP, p.Port, p.Flag1, p.Flag2, p.Flag3, p.Index)
		}
	}
}
