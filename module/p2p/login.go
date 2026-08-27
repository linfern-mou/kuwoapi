// kuwo login protocol (HTTP, captured from PC client 8.7.4.0_BDS1)
//
// Login flow (from assets/1111_new.pcapng, 2026-08-27):
//
//  1. GET http://pc.i.kuwo.cn/US_NEW/kuwo/login_kw?type=login&f=pc&q=<base64>
//     q = 172-char base64url string (128 bytes RSA-encrypted credential blob)
//     UA = "Mozilla/5.0 (Windows; U; Windows NT 5.1; ... Chrome/8.0.552.215"
//     Cookies: t3kwid=<uid>, userid=<uid>, game_mbox_id=<kid>
//
//  2. Response: HTTP 200, Content-Type: application/json;charset=UTF-8
//     body = base64url-encoded 1240-byte encrypted blob (NOT zlib)
//     Contains sid (session id), uid, various tokens
//
//  3. After login, client calls nplserver.kuwo.cn/pl.svc?op=ucheck to get
//     playlist updates (see playlist.go).
//
// Captured samples (assets/login_samples.txt):
//   Login #1: q=...BOHY=, dst=39.156.121.20:80, stream=258, sid=1072809302
//   Login #2: q=...UmWe8=, dst=39.156.123.32:80, stream=746, sid=2105522348

package p2p

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// LoginURL is the PC client login endpoint.
const LoginURL = "http://pc.i.kuwo.cn/US_NEW/kuwo/login_kw"

// LoginRequest builds the GET URL for the PC login flow.
// q is a 172-char base64url-encoded 128-byte RSA-encrypted credential blob.
func LoginRequest(q string) string {
	return fmt.Sprintf("%s?type=login&f=pc&q=%s", LoginURL, q)
}

// LoginResponse represents the decrypted login result.
type LoginResponse struct {
	UID   uint32 `json:"uid"`
	SID   string `json:"sid"`
	KID   uint32 `json:"kid"`
	Token string `json:"token,omitempty"`
	Raw   []byte // raw base64-decoded bytes (encrypted blob)
}

// DoLogin sends a login request and returns the raw base64-decoded response body.
func DoLogin(client *http.Client, q string) ([]byte, error) {
	url := LoginRequest(q)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("login read: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("login status %d", resp.StatusCode)
	}
	// Response is base64url-encoded; decode to get the encrypted blob
	decoded, err := DecodeBase64Body(body)
	if err != nil {
		return nil, fmt.Errorf("login base64 decode: %w", err)
	}
	return decoded, nil
}

// DefaultLoginUA is the User-Agent string used by the PC client.
const DefaultLoginUA = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10"

// LoginCookies returns the cookie string that must be sent with the login
// request (and persisted for subsequent requests).
func LoginCookies(uid, kid uint32) string {
	return fmt.Sprintf("t3kwid=%d; userid=%d; game_mbox_id=%d", uid, uid, kid)
}

// DecodeBase64Body base64-decodes the login response body (base64url encoding).
func DecodeBase64Body(b []byte) ([]byte, error) {
	s := strings.TrimSpace(string(b))
	// Replace URL-safe chars with standard base64
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	// Add padding
	for len(s)%4 != 0 {
		s += "="
	}
	return base64.StdEncoding.DecodeString(s)
}

// CapturedLoginQ is a real q parameter captured from the live client.
// Use this for testing; it will produce a valid login response with the
// captured session (SID=1072809302 or 2105522348 depending on which capture).
const CapturedLoginQ = "tKm7gRiP/DmpzX6THxNElivnLcO9y47B396WdUfG3j2NgwYEaodRiBlTnGY+nar4ABCM4/J5MUnPWL4oALAKjWePvVu4LHeGl0djrDUDKiF2xkzrRko3/DnYayov7va+TzekUx0qvOacGepkta5x0clnD+CVjvBgwxvkJPwBOHY="