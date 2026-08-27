// ipcheck — public IP verification API
//
// The PC client calls ipcheck.kuwo.cn to verify its public IP address.
// Used during login and periodically to check if the IP has changed.
//
// Captured request:
//
//	GET http://ipcheck.kuwo.cn/ip_check.kuwo?type=1&id=<kid>&ver=
//
// Response (plain text):
//
//	<public_ip>, ALLOW_IP
//
// Example: 117.188.0.120, ALLOW_IP

package p2p

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// IpCheckHost is the IP verification server.
const IpCheckHost = "http://ipcheck.kuwo.cn"

// IpCheckRequest builds the GET URL for the IP check API.
func IpCheckRequest(kid uint32) string {
	return fmt.Sprintf("/ip_check.kuwo?type=1&id=%d&ver=", kid)
}

// IpCheckResponse contains the parsed result.
type IpCheckResponse struct {
	PublicIP string // e.g. "117.188.0.120"
	Status   string // e.g. "ALLOW_IP"
	Raw      string
}

// DoIpCheck sends an IP check request and returns the result.
func DoIpCheck(client *http.Client, kid uint32) (*IpCheckResponse, error) {
	url := IpCheckHost + IpCheckRequest(kid)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("ipcheck request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ipcheck read: %w", err)
	}
	return ParseIpCheckBody(body)
}

// ParseIpCheckBody parses the plain-text IP check response.
// Format: "<ip>, <status>" e.g. "117.188.0.120, ALLOW_IP"
func ParseIpCheckBody(body []byte) (*IpCheckResponse, error) {
	text := strings.TrimSpace(string(body))
	parts := strings.SplitN(text, ",", 2)
	r := &IpCheckResponse{Raw: text}
	if len(parts) >= 1 {
		r.PublicIP = strings.TrimSpace(parts[0])
	}
	if len(parts) >= 2 {
		r.Status = strings.TrimSpace(parts[1])
	}
	return r, nil
}