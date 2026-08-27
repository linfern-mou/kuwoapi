// newlyric — lyrics API
//
// The PC client calls newlyric.kuwo.cn to fetch synchronized lyrics.
// The response is a custom binary format with text headers followed by
// compressed/encrypted lyrics data.
//
// Captured request:
//
//	GET http://newlyric.kuwo.cn/newlyric.lrc?<base64_encoded_rid>
//
// Response headers (before \r\n\r\n):
//	tp=content
//	path=<rid>
//	score=<int>
//	provider=<char>
//	lrc_length=<bytes>
//	cand_lrc_count=<int>
//	wiki_entry=
//	wiki_entry_sig=0
//	lrcx=1
//	show=1
//
// Response body: compressed binary (zlib or custom compression),
// approximately lrc_length bytes.

package p2p

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// NewlyricHost is the lyrics server.
const NewlyricHost = "http://newlyric.kuwo.cn"

// NewlyricRequest builds the GET URL for the lyrics API.
// rid is the song ID; the path parameter is base64-encoded.
func NewlyricRequest(rid uint64) string {
	// The captured requests use a base64-encoded path parameter
	// derived from the rid. For now we use the raw rid as captured.
	path := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", rid)))
	return fmt.Sprintf("/newlyric.lrc?%s", path)
}

// NewlyricHeaders are the text headers in the lyrics response.
type NewlyricHeaders struct {
	Type         string // "content"
	Path         string // rid as string
	Score        int
	Provider     string // "a"
	LrcLength    int    // compressed body length
	CandLrcCount int
	WikiEntry    string
	WikiEntrySig int
	Lrcx         int // 1 = synchronized lyrics
	Show         int // 1 = show
}

// NewlyricResponse is the full lyrics response.
type NewlyricResponse struct {
	Headers NewlyricHeaders
	Body    []byte // compressed lyrics data
}

// DoNewlyric sends a lyrics request and returns the response.
func DoNewlyric(client *http.Client, rid uint64) (*NewlyricResponse, error) {
	url := NewlyricHost + NewlyricRequest(rid)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("newlyric request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("newlyric status %d", resp.StatusCode)
	}
	// Read raw bytes (not through http.Response.Body which may decode)
	// Use a custom approach to get raw bytes
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("newlyric read: %w", err)
	}
	return ParseNewlyricBody(raw)
}

// ParseNewlyricBody parses the binary lyrics response.
func ParseNewlyricBody(raw []byte) (*NewlyricResponse, error) {
	r := &NewlyricResponse{}
	// Find header/body separator
	idx := strings.Index(string(raw), "\r\n\r\n")
	if idx < 0 {
		return nil, fmt.Errorf("newlyric: no header separator")
	}
	headers := raw[:idx]
	body := raw[idx+4:]
	r.Body = body

	// Parse headers
	for _, line := range strings.Split(string(headers), "\r\n") {
		line = strings.TrimSpace(line)
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key, val := line[:eq], line[eq+1:]
		switch key {
		case "tp":
			r.Headers.Type = val
		case "path":
			r.Headers.Path = val
		case "score":
			fmt.Sscanf(val, "%d", &r.Headers.Score)
		case "provider":
			r.Headers.Provider = val
		case "lrc_length":
			fmt.Sscanf(val, "%d", &r.Headers.LrcLength)
		case "cand_lrc_count":
			fmt.Sscanf(val, "%d", &r.Headers.CandLrcCount)
		case "wiki_entry":
			r.Headers.WikiEntry = val
		case "wiki_entry_sig":
			fmt.Sscanf(val, "%d", &r.Headers.WikiEntrySig)
		case "lrcx":
			fmt.Sscanf(val, "%d", &r.Headers.Lrcx)
		case "show":
			fmt.Sscanf(val, "%d", &r.Headers.Show)
		}
	}
	return r, nil
}