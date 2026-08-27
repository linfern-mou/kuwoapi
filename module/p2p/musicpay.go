// music.pay — playback settlement API
//
// The PC client calls this after selecting a song to obtain the playable URL.
// Captured request (2026-08-27, assets/1111_new.pcapng):
//
//	GET http://musicpay.kuwo.cn/music.pay?uid=<uid>&sid=<sid>&ver=&src=mbox
//	    &op=query&signver=new&action=play&ids=<rid>&accttype=1
//
// Response (HTTP 200, application/json):
//
//	{"Reason":"","errorcode":0,"errormsg":"MusicPay_OK","result":"ok",
//	 "songs":[{"MINFO":"level:ff,bitrate:2000,format:flac,size:24.29Mb;...",
//	            "url":"http://...","...":...}]}
//
// MINFO format: semicolon-separated quality levels:
//   level:ff|f|p|h|s, bitrate:<bps>, format:<flac|mp3|ogg|aac>, size:<bytes>
// The client picks the quality based on user preference (FLAC > MP3 > OGG > AAC).

package p2p

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// MusicPayHost is the playback settlement server.
const MusicPayHost = "http://musicpay.kuwo.cn"

// MusicPayRequest builds the GET URL for the music.pay settlement API.
func MusicPayRequest(uid, sid uint32, rid uint64, acctType int) string {
	return fmt.Sprintf(
		"/music.pay?uid=%d&sid=%d&ver=&src=mbox&op=query&signver=new&action=play&ids=%d&accttype=%d",
		uid, sid, rid, acctType,
	)
}

// MusicPayQuality describes one quality level from the MINFO field.
type MusicPayQuality struct {
	Level    string // "ff"=flac lossless, "f"=flac, "p"=high, "h"=medium, "s"=low
	Bitrate  int    // bits per second
	Format   string // "flac", "mp3", "ogg", "aac"
	SizeStr  string // e.g. "24.29Mb"
	SizeBytes uint64
}

// MusicPaySong is one song entry in the music.pay response.
type MusicPaySong struct {
	MINFO string `json:"MINFO"`
	URL   string `json:"url"`
	// Raw fields preserved for debugging
	Raw map[string]interface{}
}

// MusicPayResponse is the top-level music.pay response.
type MusicPayResponse struct {
	Reason   string       `json:"Reason"`
	ErrorCod int          `json:"errorcode"`
	ErrorMsg string       `json:"errormsg"`
	Result   string       `json:"result"`
	Songs    []MusicPaySong `json:"songs"`
}

// ParseMINFO parses the MINFO semicolon-separated quality list.
func ParseMINFO(minfo string) []MusicPayQuality {
	var qualities []MusicPayQuality
	for _, part := range strings.Split(minfo, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		q := MusicPayQuality{}
		for _, kv := range strings.Split(part, ",") {
			kv = strings.TrimSpace(kv)
			eq := strings.Index(kv, ":")
			if eq < 0 {
				continue
			}
			key, val := strings.TrimSpace(kv[:eq]), strings.TrimSpace(kv[eq+1:])
			switch key {
			case "level":
				q.Level = val
			case "bitrate":
				q.Bitrate, _ = strconv.Atoi(val)
			case "format":
				q.Format = val
			case "size":
				q.SizeStr = val
				q.SizeBytes = parseSizeStr(val)
			}
		}
		if q.Format != "" {
			qualities = append(qualities, q)
		}
	}
	return qualities
}

func parseSizeStr(s string) uint64 {
	s = strings.TrimSpace(s)
	// Parse "24.29Mb", "7.88Mb", "1.2Mp" etc.
	multipliers := map[string]uint64{
		"b": 1, "B": 1,
		"kb": 1024, "KB": 1024,
		"mb": 1024 * 1024, "MB": 1024 * 1024,
		"gb": 1024 * 1024 * 1024, "GB": 1024 * 1024 * 1024,
	}
	for suffix, mult := range multipliers {
		if strings.HasSuffix(s, suffix) {
			num := s[:len(s)-len(suffix)]
			var f float64
			fmt.Sscanf(num, "%f", &f)
			return uint64(f * float64(mult))
		}
	}
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

// DoMusicPay sends a music.pay request and returns the parsed response.
func DoMusicPay(client *http.Client, uid, sid uint32, rid uint64, acctType int) (*MusicPayResponse, error) {
	url := MusicPayHost + MusicPayRequest(uid, sid, rid, acctType)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("music.pay request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("music.pay read: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("music.pay status %d: %s", resp.StatusCode, body)
	}
	var result MusicPayResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("music.pay json decode: %w, body: %s", err, body)
	}
	return &result, nil
}

// BestQuality returns the highest-quality URL for a song from the music.pay response.
// Priority: flac(ff) > flac(f) > mp3 > ogg > aac.
func (r *MusicPayResponse) BestQuality() (url, format string, size uint64) {
	bestIdx := -1
	bestPriority := -1
	for i, song := range r.Songs {
		for _, q := range ParseMINFO(song.MINFO) {
			prio := formatPriority(q.Format)
			if prio > bestPriority {
				bestPriority = prio
				bestIdx = i
				format = q.Format
				size = q.SizeBytes
			}
		}
	}
	if bestIdx >= 0 {
		url = r.Songs[bestIdx].URL
	}
	return
}

func formatPriority(fmt string) int {
	switch fmt {
	case "flac":
		return 4
	case "mp3":
		return 3
	case "ogg":
		return 2
	case "aac":
		return 1
	default:
		return 0
	}
}