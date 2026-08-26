// Package p2p — PC-style resource search over plain HTTP.
//
// Reverse-engineered from KwMV.dll SearchPeer @0x1002abf0, LoadResServers
// @0x100146e0 and SearchThread @0x1002d1d0; see docs §10.65-§10.66.
//
// Wire path (ressucway=2, the variant observed live):
//
//	POST /yl_res_manage.search HTTP/1.1
//	Host: deliver.kuwo.cn
//	User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; ...)
//	Cache-Control: no-cache
//	Accept-Encoding: zlib
//	Content-Length: <len>
//	Connection: Keep-Alive
//	<body> = U_QRY text
//
// Response body has two encodings of the same logical answer:
//   - "Content-Encoding: zlib": {LE uint32 want, LE uint32 complen, zlib stream}
//   - otherwise: std base64 text of the raw plaintext
package p2p

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	resSearchPath = "/yl_res_manage.search"
	resSearchHost = "deliver.kuwo.cn"
	resSearchUA   = "Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)"
)

// ResSearchServers is the default [ResSearch] SearchServer1..8 list from the
// live config INI (u32 values interpreted big-endian per LoadResServers).
var ResSearchServers = []string{
	"101.42.130.234",
	"101.42.128.167",
	"111.206.97.45",
	"111.206.98.106",
	"49.7.250.69",
	"49.7.249.154",
	"39.156.121.53",
	"39.156.123.34",
}

// PCQueryParams carries the U_QRY fields. Computer name / user name /
// loginid stay empty: the live server rejects non-empty values with 404 and
// accepts the empty form (docs §10.66).
type PCQueryParams struct {
	Sig1    uint32 // task+0x124
	Sig2    uint32 // task+0x128
	UID     uint32 // g_login+0x7C
	NAT     uint16 // g_login+0x86
	LocalIP string // dotted quad reported as uip
}

// BuildPCUQRY renders the exact sprintf layout @0x1002aec9:
//
//	<%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|<uip:%s>|<new>|<nat:%u>|
//	<flags:%u><speer>|<ipdeny:no>%s|<loginid:%s>
func BuildPCUQRY(p PCQueryParams) string {
	return fmt.Sprintf(
		"<001><U_QRY>|<%d,%d>|<%d><>|<%s>|<rid>|<uip:%s>|<new>|<nat:%d>|<flags:0><speer>|<ipdeny:no>|<loginid:>",
		p.Sig1, p.Sig2, p.UID, p.LocalIP, p.LocalIP, p.NAT)
}

// SearchResource posts the U_QRY text to each search server in turn and
// returns the decoded plaintext reply plus the address that answered.
func SearchResource(servers []string, qry string, timeout time.Duration) ([]byte, string, error) {
	var lastErr error = errors.New("no search servers given")
	for _, srv := range servers {
		host := srv
		if _, _, err := net.SplitHostPort(srv); err != nil {
			host = net.JoinHostPort(srv, "80")
		}
		plain, err := searchOne(host, qry, timeout)
		if err == nil && len(plain) > 0 {
			return plain, host, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	return nil, "", lastErr
}

// ResSearchDebug, when set, receives every raw 200 response (header and
// body) before decoding — used to compare placeholder replies across
// networks.
var ResSearchDebug func(server string, hdr, body []byte)

func searchOne(addr, qry string, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Cache-Control: no-cache\r\n"+
			"Accept-Encoding: zlib\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: Close\r\n\r\n%s",
		resSearchPath, resSearchHost, resSearchUA, len(qry), qry)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}

	resp, err := io.ReadAll(conn)
	if err != nil && len(resp) == 0 {
		return nil, err
	}
	hdr, body, err := splitHTTP(resp)
	if err != nil {
		return nil, err
	}
	statusOK := strings.HasPrefix(string(hdr), "HTTP/") &&
		strings.Contains(strings.SplitN(string(hdr), "\r\n", 2)[0], " 200 ")
	if !statusOK {
		line := strings.SplitN(string(hdr), "\r\n", 2)[0]
		return nil, fmt.Errorf("bad status: %s", line)
	}
	if ResSearchDebug != nil {
		ResSearchDebug(addr, hdr, body)
	}
	return DecodeResBody(hdr, body)
}

// splitHTTP separates head from body on the first CRLFCRLF.
func splitHTTP(raw []byte) ([]byte, []byte, error) {
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i < 0 {
		return nil, nil, errors.New("invalid http response: no header terminator")
	}
	return raw[:i], raw[i+4:], nil
}

// DecodeResBody undoes the dual encoding (docs §10.65): binary zlib branch
// {want u32, complen u32, deflate data} or base64 text branch.
func DecodeResBody(hdr, body []byte) ([]byte, error) {
	if strings.Contains(strings.ToLower(string(hdr)), "content-encoding: zlib") {
		return decodeZlibBody(body)
	}
	txt := strings.TrimSpace(string(body))
	if txt == "" {
		return nil, errors.New("empty body")
	}
	dec, err := base64.StdEncoding.DecodeString(txt)
	if err != nil {
		// some replies may be plain text already
		if strings.Contains(txt, "FormatVer") || strings.Contains(txt, "FILE_LEN") {
			return body, nil
		}
		return nil, fmt.Errorf("base64: %w", err)
	}
	return dec, nil
}

func decodeZlibBody(body []byte) ([]byte, error) {
	if len(body) < 8 {
		return nil, errors.New("short binary body")
	}
	complen := binary.LittleEndian.Uint32(body[4:8])
	if int(complen) > len(body)-8 {
		return nil, fmt.Errorf("complen %d exceeds body %d", complen, len(body)-8)
	}
	zr, err := zlib.NewReader(bytes.NewReader(body[8 : 8+complen]))
	if err != nil {
		return nil, fmt.Errorf("zlib header: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("inflate: %w", err)
	}
	return out, nil
}

// ParseSearchServers extracts the [ResSearch] SearchServerN entries from a
// config INI, decoding the big-endian u32 IPs (LoadResServers @0x100146e0).
func ParseSearchServers(ini string) []string {
	var out []string
	for _, line := range strings.Split(ini, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "SearchServer") || strings.Contains(line, "DNS") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(line[eq+1:]), 10, 32)
		if err != nil {
			continue
		}
		u := uint32(v)
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", byte(u>>24), byte(u>>16), byte(u>>8), byte(u)))
	}
	return out
}
