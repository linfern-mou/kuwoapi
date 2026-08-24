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
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"kuwoapi/module/p2p"
)

func main() {
	sig1, sig2 := uint32(3264614461), uint32(1651339078)
	if len(os.Args) >= 3 {
		a, _ := strconv.ParseUint(os.Args[1], 10, 32)
		b, _ := strconv.ParseUint(os.Args[2], 10, 32)
		sig1, sig2 = uint32(a), uint32(b)
	}
	uid := uint32(123434546)

	fmt.Println("== stage 1: heartbeat registration ==")
	hbAddr := &net.UDPAddr{IP: net.ParseIP("211.100.49.14"), Port: 25607}
	trkAddr := &net.UDPAddr{IP: net.ParseIP(net.JoinHostPort("", "")), Port: 0}
	if ips, err := net.LookupIP("deliver.kuwo.cn"); err == nil && len(ips) > 0 {
		trkAddr = &net.UDPAddr{IP: ips[0], Port: 25607}
		fmt.Println("tracker resolves to", trkAddr)
	} else {
		return
	}

	uc, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		fmt.Println("bind:", err)
		return
	}
	defer uc.Close()

	for i := 0; i < 5; i++ {
		hb := p2p.Heartbeat{Seq: uint8(i), UID: uid, NAT: 3, Port: uint16(uc.LocalAddr().(*net.UDPAddr).Port)}
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

	fmt.Println("\n== stage 2: CSF session + U_QRY ==")
	sess, err := p2p.Dial("", trkAddr)
	if err != nil {
		fmt.Println("handshake:", err)
		fmt.Println("(no SYNACK — either the legacy tracker is gone or a firewall eats UDP)")
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
