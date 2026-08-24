package p2p

import (
	"fmt"
	"strconv"
	"strings"
)

// U_QRY is the resource-query request text KwMV sends over a CSF session to
// the tracker (deliver.kuwo.cn:25607). Layout recovered at 0x1002aec9:
//
//	<%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|<uip:%s>|<new>|<nat:%u>|
//	<flags:%u><speer>|<ipdeny:no>%s|<loginid:%s>
type QueryParams struct {
	UID      uint32 // g_login+0x7C
	Sig1     uint32 // task+0x124
	Sig2     uint32 // task+0x128
	Ver      string // client version string
	NAT      uint16 // g_login+0x86 (initial 3)
	LocalIP  string // dotted quad of external IP
	IPDeny   string // ipdeny list flag ("no" when absent)
	LoginID  string
	CdnSpeed bool // CdnSpeedPolicy=Enable appends |<cdnreq>
}

// BuildUQRY renders the request text.
func BuildUQRY(p QueryParams) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<001><U_QRY>|<%d,%d>|<%d>", p.Sig1, p.Sig2, p.UID)
	b.WriteString("<speer>|")
	fmt.Fprintf(&b, "<rid>|<uip:%s>|<new>|<nat:%d>|", p.LocalIP, p.NAT)
	fmt.Fprintf(&b, "<ipdeny:%s>", p.IPDeny)
	if p.CdnSpeed {
		b.WriteString("|<cdnreq>")
	}
	fmt.Fprintf(&b, "|<loginid:%s>\r\n", p.LoginID)
	_ = p.Ver
	return b.String()
}

// Peer is one entry from the PEERS section of the tracker response.
type Peer struct {
	Kid    uint32
	IP     string
	Port   uint16
	Flag1  int32
	Flag2  int32
	Flag3  int32
	Index  uint32
}

// Response is the parsed tracker answer. Wire format (plaintext):
//
//	FormatVer:1.1|sig:(sig1,sig2)|searchtm:47|PEERS:(...)(...)
//	FILE_LEN<12345><URL>http://a<URL>http://b...
type Response struct {
	FormatVer   string
	Sig1, Sig2  uint64
	SearchTM    uint32
	Peers       []Peer
	FileLen     int64
	URLs        []string
	Denied      bool // <DENY_IP>
	ResourceDel bool // <RES_DEL>
}

// ParseResponse decodes the plaintext reply per the state machine at
// 0x1002b9f6: DENY_IP and RES_DEL short-circuit; FILE_LEN yields the size;
// repeated <URL>x< segments list server links; PEERS holds "(kid,ip,port,
// f1,f2,f3,idx)" tuples.
func ParseResponse(text string) *Response {
	r := &Response{}
	switch {
	case strings.Contains(text, "<DENY_IP>"):
		r.Denied = true
		return r
	case strings.Contains(text, "<RES_DEL>"):
		r.ResourceDel = true
		return r
	}
	if i := strings.Index(text, "FormatVer:"); i >= 0 {
		rest := text[i+len("FormatVer:"):]
		if j := strings.IndexAny(rest, "| \r\n"); j >= 0 {
			r.FormatVer = rest[:j]
		} else {
			r.FormatVer = rest
		}
	}
	if i := strings.Index(text, "searchtm:"); i >= 0 {
		rest := text[i+len("searchtm:"):]
		end := strings.IndexAny(rest, "|")
		if end >= 0 {
			v, _ := strconv.ParseUint(strings.TrimSpace(rest[:end]), 10, 32)
			r.SearchTM = uint32(v)
		}
	}
	if i := strings.Index(text, "FILE_LEN"); i >= 0 {
		// wire form: FILE_LEN<n>  (find '<' then digits up to '>', cf. 0x1002be8d)
		rest := text[i+len("FILE_LEN"):]
		if lt := strings.IndexByte(rest, '<'); lt >= 0 {
			rest = rest[lt+1:]
			if end := strings.IndexByte(rest, '>'); end > 0 {
				n, _ := strconv.ParseInt(strings.TrimSpace(rest[:end]), 10, 64)
				r.FileLen = n
			}
		}
	}
	rest := text
	for {
		k := strings.Index(rest, "<URL>")
		if k < 0 {
			break
		}
		start := k + len("<URL>")
		j := strings.IndexByte(rest[start:], '<')
		if j < 0 {
			if u := rest[start:]; u != "" {
				r.URLs = append(r.URLs, u)
			}
			break
		}
		if u := rest[start : start+j]; u != "" {
			r.URLs = append(r.URLs, u)
		}
		rest = rest[start+j:]
	}
	if i := strings.Index(text, "PEERS:"); i >= 0 {
		r.Peers = parsePeers(text[i+len("PEERS:"):])
	}
	return r
}

// parsePeers scans "(kid,ip,port,f1,f2,f3,idx)" tuples.
func parsePeers(s string) []Peer {
	var out []Peer
	for i := 0; i < len(s); {
		open := strings.IndexByte(s[i:], '(')
		if open < 0 {
			break
		}
		i += open + 1
		close_ := strings.IndexByte(s[i:], ')')
		if close_ < 0 {
			break
		}
		body := s[i : i+close_]
		i += close_ + 1
		parts := strings.SplitN(body, ",", 7)
		if len(parts) != 7 {
			continue
		}
		var p Peer
		kid, _ := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
		p.Kid = uint32(kid)
		p.IP = strings.TrimSpace(parts[1])
		port, _ := strconv.ParseUint(strings.TrimSpace(parts[2]), 10, 16)
		p.Port = uint16(port)
		f1, _ := strconv.Atoi(strings.TrimSpace(parts[3]))
		p.Flag1 = int32(f1)
		f2, _ := strconv.Atoi(strings.TrimSpace(parts[4]))
		p.Flag2 = int32(f2)
		f3, _ := strconv.Atoi(strings.TrimSpace(parts[5]))
		p.Flag3 = int32(f3)
		idx, _ := strconv.ParseUint(strings.TrimSpace(parts[6]), 10, 32)
		p.Index = uint32(idx)
		out = append(out, p)
	}
	return out
}
