// Package p2p — config.kuwo.cn server-pushed configuration channel.
//
// Reverse-engineered from KwModConfig.dll @0x1000ed30 (request build) and
// KwLib.dll Base64Encode @0x10013fd0 (encoding); see docs §10.59/§10.60.
//
// Wire format:
//
//	GET http://config.kuwo.cn/uc/s?m=<len(plain)>;<b64>
//	plain = "<uid>;<version>,<installsrc>,config"
//	b64   = std_base64(XOR_repeating(plain, "yeelion "))
//
// Response body is plain std-base64 of an INI document (no XOR layer).
package p2p

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	configURL    = "http://config.kuwo.cn/uc/s?m="
	xorKey       = "yeelion "
	defaultVer   = "MUSIC_8.7.4.0_BDS1"
	defaultSrc   = "kwmusic_web_1_bds_20171206"
	configClient = "KwMusic"
)

var configHTTPClient = &http.Client{Timeout: 10 * time.Second}

// SetConfigResolver injects a custom DNS resolver for the config endpoint.
// Required on Android where the default resolver reads /etc/resolv.conf and
// falls back to [::1]:53 (refused).
func SetConfigResolver(r *net.Resolver) {
	configHTTPClient.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 5 * time.Second, Resolver: r}
			return d.DialContext(ctx, network, addr)
		},
	}
}

func xorYeelion(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ xorKey[i%len(xorKey)]
	}
	return out
}

// BuildConfigURL encodes the /uc/s?m= request for the given payload fields.
func BuildConfigURL(uid, version, installSrc string) string {
	if version == "" {
		version = defaultVer
	}
	if installSrc == "" {
		installSrc = defaultSrc
	}
	plain := fmt.Sprintf("%s;%s,%s,config", uid, version, installSrc)
	enc := base64.StdEncoding.EncodeToString(xorYeelion([]byte(plain)))
	return configURL + strconv.Itoa(len(plain)) + ";" + enc
}

// FetchServerConfig pulls the live pushed-config INI from config.kuwo.cn.
// The tail field and uid are not validated by the server; empty values fall
// back to the known-good defaults.
func FetchServerConfig(uid string) (string, error) {
	resp, err := configHTTPClient.Get(BuildConfigURL(uid, "", ""))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(body))
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("config: response not base64 (%d bytes): %w", len(body), err)
	}
	txt := string(raw)
	if txt == "" || strings.HasPrefix(txt, "FAIL") {
		return "", errors.New("config: server returned FAIL")
	}
	return txt, nil
}

// INIGet extracts one key's value from the fetched INI text (first match,
// case-sensitive section/key like [p2p] HeartbeatServer=...).
func INIGet(ini, key string) string {
	for _, line := range strings.Split(ini, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 && strings.TrimSpace(line[:i]) == key {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

// HeartbeatServersFromConfig parses "ip:port,ip:port" from HeartbeatServer.
func HeartbeatServersFromConfig(ini string) []string {
	v := INIGet(ini, "HeartbeatServer")
	if v == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, ":") {
			out = append(out, part)
		}
	}
	return out
}

// SearchServersFromConfig decodes [ResSearch] SearchServerN uint32 values as
// big-endian IPv4 (verified: 664566069 -> 39.156.121.53 matches resserver in
// live act.log). Returns dotted IPs in N order.
func SearchServersFromConfig(ini string) []string {
	var out []string
	for n := 1; ; n++ {
		v := INIGet(ini, fmt.Sprintf("SearchServer%d", n))
		if v == "" {
			break
		}
		u, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			continue
		}
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", byte(u>>24), byte(u>>16), byte(u>>8), byte(u)))
	}
	return out
}
