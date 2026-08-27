// pan — cloud storage API
//
// The PC client calls pan.kuwo.cn to list songs in the user's cloud library.
//
// Captured request:
//
//	GET http://pan.kuwo.cn/pan?type=get&devid=<devid>&uid=<uid>
//	    &sid=<sid>&client=pc&src=&pi=0&pn=30000
//
// Response (JSON):
//
//	{"result":"ok","count":2,"list":[
//	  {"sign":"...","enc":"0","mid":"...","isRedSong":0,
//	   "albumpic":"http://...",
//	   "songname":"...","artist":"...","album":"...",
//	   "format":"flac","size":...},
//	  ...
//	]}

package p2p

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// PanHost is the cloud storage server.
const PanHost = "http://pan.kuwo.cn"

// PanRequest builds the GET URL for the cloud storage API.
func PanRequest(devid, uid uint32, sid uint32, pageIdx, pageSize int) string {
	return fmt.Sprintf(
		"/pan?type=get&devid=%d&uid=%d&sid=%d&client=pc&src=&pi=%d&pn=%d",
		devid, uid, sid, pageIdx, pageSize,
	)
}

// PanSong is one song in the cloud library.
type PanSong struct {
	Sign      string `json:"sign"`
	Enc       string `json:"enc"`
	MID       string `json:"mid"`
	IsRedSong int    `json:"isRedSong"`
	AlbumPic  string `json:"albumpic"`
	SongName  string `json:"songname"`
	Artist    string `json:"artist"`
	Album     string `json:"album"`
	Format    string `json:"format"`
	Size      int64  `json:"size"`
}

// PanResponse is the top-level cloud storage response.
type PanResponse struct {
	Result string    `json:"result"`
	Count  int       `json:"count"`
	List   []PanSong `json:"list"`
}

// DoPan sends a cloud storage request and returns parsed results.
func DoPan(client *http.Client, devid, uid, sid uint32, pageIdx, pageSize int) (*PanResponse, error) {
	url := PanHost + PanRequest(devid, uid, sid, pageIdx, pageSize)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("pan request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("pan read: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("pan status %d: %s", resp.StatusCode, body)
	}
	var result PanResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("pan json decode: %w, body: %s", err, body)
	}
	return &result, nil
}