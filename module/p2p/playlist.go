// Playlist update protocol (nplserver.kuwo.cn/pl.svc)
//
// The PC client calls op=ucheck after login to sync playlists.
// Captured request (2026-08-27, assets/1111_new.pcapng):
//
//	GET /pl.svc?op=ucheck&fmt=km&client=kwmusic&compress=yes&bigid=1&pcmp4=1&encode=utf-8&uid=88594783&sid=1072809302
//
// Response body format (one entry per line, \r\n separator):
//
//	name=<playlist_name>;pid=<playlist_id>;ver=<version>;type=<type>;op=<UPDATE|CHECK>;tmpid=<id>;data=<song_ids_comma_separated>
//	name=<playlist_name>;pid=<playlist_id>;ver=<version>;type=<type>;op=<UPDATE|CHECK>;tmpid=<id>;data=;sig=<signature>
//
// type values observed:
//   PC_DEFAULT  - main PC playlist (name decodes to "我的音乐" in GBK)
//   MOBI_DEFAULT - mobile default playlist
//   MYFAVORITE  - favorites (name decodes to "我的收藏")
//   GENERAL     - general/shared playlist
//   RADIO       - radio playlist
//
// op values:
//   UPDATE - playlist has new songs (data field contains comma-separated song IDs)
//   CHECK  - no changes (sig field contains a signature hash)
//
// Captured response (frame 44630, tcp.stream=816):
//   PC_DEFAULT pid=43815947 ver=465 UPDATE -> 27 songs
//   MOBI_DEFAULT pid=43815949 ver=6 CHECK sig=0
//   MYFAVORITE pid=43815945 ver=30 CHECK sig=3861835964
//   + more GENERAL/RADIO entries

package p2p

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// PlaylistEntry is one row in the ucheck response.
type PlaylistEntry struct {
	Name  string // GBK-encoded playlist name (e.g. "我的音乐" -> "PC_DEFAULT" type)
	PID   uint64 // Playlist ID
	Ver   uint32 // Version number
	Type  string // PC_DEFAULT, MOBI_DEFAULT, MYFAVORITE, GENERAL, RADIO
	Op    string // UPDATE or CHECK
	TMPID int    // Temporary ID used in the request
	Data  []uint64 // Song IDs (for UPDATE entries)
	Sig   uint64 // Signature hash (for CHECK entries)
}

// UCheckRequest builds the GET URL for the playlist sync request.
func UCheckRequest(uid, sid uint32) string {
	return fmt.Sprintf(
		"/pl.svc?op=ucheck&fmt=km&client=kwmusic&compress=yes&bigid=1&pcmp4=1&encode=utf-8&uid=%d&sid=%d",
		uid, sid,
	)
}

// UCheckHost is the host for the playlist sync endpoint.
const UCheckHost = "http://nplserver.kuwo.cn"

// FetchPlaylistUpdate sends a ucheck request and returns parsed entries.
func FetchPlaylistUpdate(client *http.Client, uid, sid uint32) ([]PlaylistEntry, error) {
	url := UCheckHost + UCheckRequest(uid, sid)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("ucheck request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ucheck read: %w", err)
	}
	return ParsePlaylistResponse(body)
}

// ParsePlaylistResponse parses the ucheck response body into entries.
// The name field is GBK-encoded; callers should decode if needed.
func ParsePlaylistResponse(body []byte) ([]PlaylistEntry, error) {
	var entries []PlaylistEntry
	for _, line := range strings.Split(string(body), "\r\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		e, err := parsePlaylistLine(line)
		if err != nil {
			return nil, fmt.Errorf("parse entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func parsePlaylistLine(line string) (PlaylistEntry, error) {
	var e PlaylistEntry
	parts := strings.Split(line, ";")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := kv[0], kv[1]
		switch key {
		case "name":
			e.Name = val
		case "pid":
			e.PID, _ = strconv.ParseUint(val, 10, 64)
		case "ver":
			v, _ := strconv.ParseUint(val, 10, 32)
			e.Ver = uint32(v)
		case "type":
			e.Type = val
		case "op":
			e.Op = val
		case "tmpid":
			e.TMPID, _ = strconv.Atoi(val)
		case "data":
			e.Data = parseSongIDs(val)
		case "sig":
			e.Sig, _ = strconv.ParseUint(val, 10, 64)
		}
	}
	return e, nil
}

func parseSongIDs(s string) []uint64 {
	var ids []uint64
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if id, err := strconv.ParseUint(part, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// PrintPlaylistEntries prints playlist entries in a human-readable format.
func PrintPlaylistEntries(entries []PlaylistEntry) {
	for _, e := range entries {
		switch e.Op {
		case "UPDATE":
			fmt.Printf("  [UPDATE] %s (pid=%d ver=%d type=%s) -> %d songs\n",
				e.Name, e.PID, e.Ver, e.Type, len(e.Data))
			if len(e.Data) <= 10 {
				fmt.Printf("    songs: %v\n", e.Data)
			} else {
				fmt.Printf("    songs (first 10): %v\n", e.Data[:10])
			}
		case "CHECK":
			fmt.Printf("  [CHECK]  %s (pid=%d ver=%d type=%s) sig=%d\n",
				e.Name, e.PID, e.Ver, e.Type, e.Sig)
		}
	}
}

// CapturedPlaylistResponse is the raw ucheck response from the live capture
// (frame 44630, tcp.stream=816, 2026-08-27). The name fields are GBK-encoded.
var CapturedPlaylistResponse = []byte(
	"name=\xe1\xa3\xac\xb4\xca\xb4\xf3\xc4\xdc\xbf\xe9;pid=43815947;ver=465;type=PC_DEFAULT;op=UPDATE;tmpid=31;" +
		"data=228908,440613,450444,118987,324244,324243,440615,94237,133360,320462,1044318,611037129,157535068," +
		"146192071,60010947,75897710,219226340,568213041,221822646,521282545,5844591,550221152,595898177," +
		"193290598,941528,395772351,1108461\r\n" +
		"name=\xe1\xa3\xac\xb4\xca\xb4\xf3\xc4\xdc\xbf\xe9;pid=43815949;ver=6;type=MOBI_DEFAULT;op=CHECK;tmpid=32;" +
		"data=;sig=0\r\n" +
		"name=\xe1\xa3\xac\xb4\xca\xb4\xf3\xc4\xdc\xbf\xe9;pid=43815945;ver=30;type=MYFAVORITE;op=CHECK;tmpid=34;" +
		"data=;sig=3861835964\r\n",
)