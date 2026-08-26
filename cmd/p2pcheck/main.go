// Command p2pcheck runs the recovered KwMV P2P handshake against the live
// tracker so the chain can be verified on a network with unrestricted UDP
// (the dev sandbox drops outbound UDP entirely).
//
// Usage:
//
//	go run ./cmd/p2pcheck [sig1 sig2 [rid]]
//
// With a rid but no sig pair the tool walks the full pd.dll DownTask chain:
// r.s musicinfo -> embedded S1/S2 (fallback: rid.kuwo.cn/sig.s) -> U_QRY.
// e.g. legacy pair for MUSIC_169753: 3264614461 1651339078
package main

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"kuwoapi/module/p2p"
)

// public DNS used because Android lacks /etc/resolv.conf
const dnsServer = "8.8.8.8:53"

func main() {
	sig1, sig2 := uint32(3264614461), uint32(1651339078)
	// anonymous uid per KwMV.dll 0x10012b21: (FNV1a(machine) mod 1e8) + 1e8;
	// act.log kid field confirms the live value is 15277654 (docs §10.65)
	uid := uint32(15277654)
	var ridArg string
	if len(os.Args) >= 3 {
		a, _ := strconv.ParseUint(os.Args[1], 10, 32)
		b, _ := strconv.ParseUint(os.Args[2], 10, 32)
		sig1, sig2 = uint32(a), uint32(b)
	}
	if len(os.Args) >= 4 {
		ridArg = strings.TrimPrefix(os.Args[3], "MUSIC_")
	} else if len(os.Args) == 2 {
		// single-arg form: ./p2pcheck MUSIC_<rid> walks the full DownTask chain
		if _, err := strconv.ParseUint(os.Args[1], 10, 64); err == nil || strings.HasPrefix(os.Args[1], "MUSIC_") {
			ridArg = strings.TrimPrefix(os.Args[1], "MUSIC_")
			sig1, sig2 = 0, 0 // force musicinfo/sig.s path like a real client click
		}
	}
	if sig1 == 0 && ridArg == "" {
		fmt.Println("usage: p2pcheck [MUSIC_<rid>] | [sig1 sig2 [rid]]")
		os.Exit(2)
	}

	fmt.Println("\n== stage 0: UDP egress sanity (standard DNS over UDP) ==")
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

	fmt.Println("\n== stage 0.5: pull live server list from config.kuwo.cn ==")
	// Android has no /etc/resolv.conf so Go's resolver defaults to [::1]:53 and
	// fails; query a public DNS explicitly instead.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}
	p2p.SetConfigResolver(resolver)
	hbAddrs := []*net.UDPAddr{}
	trkAddrs := []*net.UDPAddr{}
	helpAddrs := []*net.UDPAddr{}
	liveINI := ""
	if ini, err := p2p.FetchServerConfig(strconv.FormatUint(uint64(uid), 10)); err != nil {
		fmt.Println("config fetch failed:", err)
	} else {
		liveINI = ini
		fmt.Printf("config INI %d bytes\n", len(ini))
		for _, s := range p2p.HeartbeatServersFromConfig(ini) {
			if ip, port, err := net.SplitHostPort(s); err == nil {
				hbAddrs = append(hbAddrs, &net.UDPAddr{IP: net.ParseIP(ip), Port: mustAtoi(port)})
			}
		}
		for _, ipStr := range p2p.SearchServersFromConfig(ini) {
			trkAddrs = append(trkAddrs, &net.UDPAddr{IP: net.ParseIP(ipStr), Port: 25607})
		}
		fmt.Println("heartbeat servers:", hbAddrs)
		fmt.Println("search/tracker servers:", trkAddrs)
		// dump the live [ResSearch] section verbatim: these are the HTTP
		// search endpoints the current client generation actually uses
		if i := strings.Index(ini, "[ResSearch]"); i >= 0 {
			sec := ini[i:]
			if j := strings.Index(sec[1:], "\n["); j >= 0 {
				sec = sec[:j+1]
			}
			fmt.Printf("--- live [ResSearch] section ---\n%s-------------------------------\n", sec)
		}
	}
	if len(hbAddrs) == 0 {
		hbAddrs = append(hbAddrs, &net.UDPAddr{IP: net.ParseIP("175.102.178.96"), Port: 25607})
	}

	fmt.Println("\n== stage 1: heartbeat registration ==")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// deliver.kuwo.cn DNS IPs stay first in the tracker list (act.log evidence)
	ips, err := resolver.LookupNetIP(ctx, "ip4", "deliver.kuwo.cn")
	if err == nil && len(ips) > 0 {
		for _, ip := range ips {
			a := &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: 25607}
			dup := false
			for _, t := range trkAddrs {
				if t.IP.String() == a.IP.String() {
					dup = true
					break
				}
			}
			if !dup {
				trkAddrs = append([]*net.UDPAddr{a}, trkAddrs...)
			}
		}
		fmt.Println("tracker resolves to", ips)
	}
	if len(trkAddrs) == 0 {
		trkAddrs = append(trkAddrs, &net.UDPAddr{IP: net.ParseIP("39.156.121.53"), Port: 25607})
	}

	uc, err := net.ListenUDP("udp", &net.UDPAddr{Port: 6000})
	if err != nil {
		fmt.Printf("bind :6000 failed (%v), using ephemeral port\n", err)
		uc, err = net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			fmt.Println("bind:", err)
			return
		}
	}
	fmt.Printf("local udp port: %d (server-pushed P2P port is 6000)\n", uc.LocalAddr().(*net.UDPAddr).Port)
	p2p.Verbose = true

	// outbound IP for the probe packet
	conn, err := net.DialTimeout("udp", dnsServer, 3*time.Second)
	if err != nil {
		fmt.Println("local ip probe:", err)
		return
	}
	localIP := net.ParseIP(conn.LocalAddr().(*net.UDPAddr).IP.String()).To4()
	conn.Close()
	lport := uint16(uc.LocalAddr().(*net.UDPAddr).Port)

	// help servers from libp2p.so defaults (P2P_HelpSvr1/2, docs §10.62)
	for _, h := range p2p.DefaultHelpServers {
		host, port, _ := net.SplitHostPort(h)
		ha, err := resolver.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			fmt.Printf("resolve %s: %v\n", host, err)
			continue
		}
		helpAddrs = append(helpAddrs, &net.UDPAddr{IP: net.IP(ha[0].AsSlice()), Port: mustAtoi(port)})
	}
	targets := append(append([]*net.UDPAddr{}, helpAddrs...), hbAddrs...)
	targets = append(targets, trkAddrs...)

	seq := uint8(1)
	probe := p2p.NATProbe(seq, uid, binary.BigEndian.Uint32(localIP), lport)
	fmt.Println("== stage 1a: Android-protocol NAT probe (cmd 0x29, keepalive) ==")
	fmt.Printf("probe %dB -> %d targets\n", len(probe), len(targets))
	sawReply := false
	var extIP uint32
	var extPort uint16
	for i := 0; i < 5; i++ {
		for _, a := range targets {
			uc.WriteTo(probe, a)
		}
		buf := make([]byte, 2048)
		deadline := time.Now().Add(time.Duration(len(targets)) * 400 * time.Millisecond)
		for time.Now().Before(deadline) {
			uc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, from, err := uc.ReadFrom(buf)
			if err != nil {
				break
			}
			sawReply = true
			class, cmd, payload, ok := p2p.Classify(buf[:n])
			fmt.Printf("REPLY from %v (%dB) class=%d cmd=0x%02x\n", from, n, class, cmd)
			fmt.Print(hex.Dump(buf[:n]))
			if !ok {
				continue
			}
			switch cmd {
			case p2p.CmdNATProbeACK:
				if ip, port, ok := p2p.NATProbeACK(payload, uid); ok {
					extIP, extPort = ip, port
					fmt.Printf("  -> TNATProbeMsg ext=%d.%d.%d.%d:%d nat=0/2/4 tree applies\n",
						byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), port)
				}
			case p2p.CmdHeartbeatACK:
				if ip, port, ok := p2p.HeartbeatACK(payload); ok {
					extIP, extPort = ip, port
					fmt.Printf("  -> ACK_HEARTBEAT_INFO ext=%d.%d.%d.%d:%d\n",
						byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), port)
				}
			case p2p.CmdPassiveConnect:
				if ip, port, ok := p2p.PassiveConnectReq(payload); ok {
					fmt.Printf("  -> PASSIVE CONNECT to %d.%d.%d.%d:%d\n",
						byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), port)
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if sawReply && extIP != 0 {
		ip := localIP
		fmt.Printf("registered! external endpoint %d.%d.%d.%d:%d (local %s:%d)\n",
			byte(extIP>>24), byte(extIP>>16), byte(extIP>>8), byte(extIP), extPort, ip, lport)
	} else if sawReply {
		fmt.Println("replies seen but no external endpoint extracted yet")
	} else if stage0OK {
		fmt.Println("(no reply to cmd 0x29 while DNS-over-UDP works -> format or target mismatch)")
	}

	fmt.Println("\n== stage 1b: legacy PC heartbeat (KwMV 0xE2103) as control ==")
	hbZero := p2p.Heartbeat{UID: uid, NAT: 3, Port: lport, IP: 0}
	for i := 0; i < 2; i++ {
		for _, a := range targets {
			uc.WriteTo(hbZero.Marshal(), a)
		}
		buf := make([]byte, 2048)
		deadline := time.Now().Add(time.Duration(len(targets)) * 400 * time.Millisecond)
		for time.Now().Before(deadline) {
			uc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, from, err := uc.ReadFrom(buf)
			if err != nil {
				break
			}
			fmt.Printf("REPLY from %v (%dB): % x\n", from, n, buf[:n])
		}
		time.Sleep(300 * time.Millisecond)
	}

	uc.Close() // free :6000 for the stage-2 sessions

	fmt.Println("\n== stage 1c: PC-style HTTP resource search (TCP:80, ressucway=2) ==")
	{
		p2p.ResSearchDebug = func(server string, hdr, body []byte) {
			i := bytes.Index(hdr, []byte("\r\n\r\n"))
			if i >= 0 {
				hdr = hdr[:i]
			}
			fmt.Printf("RAW from %s\n--- header ---\n%s\n--- body (%dB) ---\n%s\n",
				server, hdr, len(body), hex.Dump(body))
		}
		servers := make([]string, 0, len(trkAddrs)+len(p2p.ResSearchServers))
		if live := p2p.ParseSearchServers(liveINI); len(live) > 0 {
			fmt.Println("live [ResSearch] SearchServer list:", live)
			servers = append(servers, live...)
		}
		for _, a := range trkAddrs {
			servers = append(servers, a.IP.String())
		}
		servers = append(servers, p2p.ResSearchServers...)

		// Full pd.dll chain: click -> musicinfo -> sig decision -> U_QRY.
		searchRid := ridArg
		if searchRid == "" {
			searchRid = "228720849"
			fmt.Println("no rid arg; using default 228720849 (sig must match!)")
		}

		// Step A: KwSongCache.dll musicinfo call (first thing after click).
		sigSrc := "argv"
		fmt.Printf("\n[musicinfo] GET r.s ids=MUSIC_%s ...\n", searchRid)
		qSigs, formats, err := fetchMusicInfo(searchRid)
		if err != nil {
			fmt.Println("  musicinfo failed:", err)
			fmt.Println("  (server returns an empty zlib body for untrusted IPs)")
		} else {
			fmt.Printf("  FORMATS=%v\n", formats)
			for q, s := range qSigs {
				fmt.Printf("  %-10s sig=%d,%d\n", q, s[0], s[1])
			}
			if len(qSigs) == 0 {
				fmt.Println("  no embedded S1/S2 in reply")
			} else if len(os.Args) < 3 {
				// pd.dll DownTask: task.sig comes pre-filled from metadata.
				// Prefer the formats the PC client actually plays.
				var pick [2]uint64
				for _, q := range []string{"MP3128", "ALFLAC", "MP3H", "AAC48", "OGG192", "WMA128"} {
					if s, ok := qSigs[q]; ok {
						pick = s
						break
					}
				}
				if pick[0] == 0 {
					for _, s := range qSigs {
						pick = s
						break
					}
				}
				sig1, sig2 = uint32(pick[0]), uint32(pick[1])
				sigSrc = "musicinfo S1/S2"
				fmt.Printf("  -> using metadata sig %d,%d\n", sig1, sig2)
			}
		}

		// Step B: sig empty? -> pd.dll GetResourceSig via rid.kuwo.cn/sig.s.
		if ridArg != "" && sigSrc != "musicinfo S1/S2" {
			fmt.Printf("\n[sig.s] signing rid %s ...\n", searchRid)
			a, b, err := p2p.FetchSig(ridArg, 8*time.Second)
			if err != nil {
				fmt.Println("  sig fetch failed:", err)
				fmt.Println("  -> falling back to argv/metadata sig; mismatch yields placeholder reply")
			} else {
				sig1, sig2 = a, b
				sigSrc = "sig.s fresh"
				fmt.Printf("  fresh sig: %d,%d\n", sig1, sig2)
			}
		}
		fmt.Printf("[sig source] %s -> %d,%d\n", sigSrc, sig1, sig2)
		if sig1 == 0 {
			fmt.Println("no usable sig (musicinfo empty + sig.s unreachable) - cannot search")
			return
		}

		p2p.SearchAttemptLog = func(addr, status string) {
			fmt.Printf("  [%s] %s\n", addr, status)
		}
		// Original client sends the literal <rid> slot (sig pair is the key).
		// Try that first; on 404 retry with the numeric rid as a fallback.
		qry := p2p.BuildPCUQRY(p2p.PCQueryParams{
			Sig1: sig1, Sig2: sig2, UID: uid,
			NAT: 3, LocalIP: "192.168.1.8",
		})
		fmt.Printf("U_QRY (%dB):\n%s\n", len(qry), qry)
		plain, via, err := p2p.SearchResource(servers, qry, 6*time.Second)
		if err != nil {
			fmt.Println("literal-rid search failed:", err)
			qry = p2p.BuildPCUQRY(p2p.PCQueryParams{
				Sig1: sig1, Sig2: sig2, UID: uid,
				NAT: 3, LocalIP: "192.168.1.8", RidOverride: searchRid,
			})
			fmt.Printf("retry with numeric rid (%dB):\n%s\n", len(qry), qry)
			plain, via, err = p2p.SearchResource(servers, qry, 6*time.Second)
		}
		if err != nil {
			fmt.Println("http search failed:", err)
		} else {
			fmt.Printf("reply from %s: %d bytes plaintext\n%s\n", via, len(plain), plain)
			r := p2p.ParseResponse(string(plain))
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
				for _, pp := range r.Peers {
					fmt.Printf("  PEER kid=%d %s:%d flags=%d,%d,%d idx=%d\n",
						pp.Kid, pp.IP, pp.Port, pp.Flag1, pp.Flag2, pp.Flag3, pp.Index)
				}
			}
		}
	}

	fmt.Println("\n== stage 2: CSF session + U_QRY (3 attempts per tracker) ==")
	var sess *p2p.Session
outer:
	for _, trk := range trkAddrs {
		for attempt := 1; attempt <= 3; attempt++ {
			src := ""
			if uc.LocalAddr().(*net.UDPAddr).Port == 6000 {
				src = ":6000"
			}
			s, err := p2p.Dial(src, trk, uid)
			if err == nil {
				sess = s
				fmt.Printf("handshake OK via %v on attempt %d (lport=%d)\n", trk, attempt, s.LocalPort())
				break outer
			}
			fmt.Printf("%v attempt %d: %v\n", trk, attempt, err)
			time.Sleep(500 * time.Millisecond)
		}
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

// httpClientWithUDPResolver builds an HTTP client whose dialer resolves
// hostnames via public UDP DNS instead of the broken Android/Termux
// system resolver ([::1]:53 -> connection refused).
func httpClientWithUDPResolver() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				if net.ParseIP(host) != nil {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}
				for _, dns := range []string{"192.168.1.1:53", "223.5.5.5:53", "114.114.114.114:53", "8.8.8.8:53"} {
					ip, err := p2p.ResolveViaUDP(dns, host, 3*time.Second)
					if err == nil && ip != "" {
						return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip, port))
					}
				}
				// fall back to whatever the OS resolver can do
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
}

// fetchMusicInfo mirrors KwSongCache.dll / song.go: GET r.s?stype=musicinfo,
// body is an 8-byte header followed by a zlib stream of key=value lines.
// Quality lines look like "<qname>=S1:<n>|S2:<n>|SIZE:<n>|BT:<n>".
func fetchMusicInfo(rid string) (map[string][2]uint64, []string, error) {
	u := fmt.Sprintf(
		"http://search.kuwo.cn/r.s?stype=musicinfo&itemset=music_2014&alflac=1&pcmp4=1&ids=MUSIC_%s",
		rid)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Kuwo_Music_Box")
	resp, err := httpClientWithUDPResolver().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) < 10 {
		return nil, nil, fmt.Errorf("empty body (%d bytes)", len(raw))
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw[8:]))
	if err != nil {
		return nil, nil, err
	}
	text, err := io.ReadAll(zr)
	if err != nil {
		return nil, nil, err
	}

	var formats []string
	sep := "|"
	sigs := map[string][2]uint64{}
	for _, line := range strings.Split(string(text), "\n") {
		line = strings.TrimSpace(line)
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key, val := strings.TrimSpace(line[:eq]), line[eq+1:]
		switch {
		case key == "FORMATS":
			v := strings.TrimSpace(val)
			sep = "|"
			if strings.Contains(v, "$") {
				sep = "$"
			}
			formats = strings.Split(v, sep)
		case strings.Contains(val, "S1:"):
			var s1, s2 uint64
			for _, p := range strings.Split(val, "|") {
				ci := strings.Index(p, ":")
				if ci < 0 {
					continue
				}
				v, _ := strconv.ParseUint(strings.TrimSpace(p[ci+1:]), 10, 64)
				switch p[:ci] {
				case "S1":
					s1 = v
				case "S2":
					s2 = v
				}
			}
			if s1 != 0 {
				sigs[key] = [2]uint64{s1, s2}
			}
		}
	}
	return sigs, formats, nil
}

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}
