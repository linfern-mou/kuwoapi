// datacenter — alternative music info API
//
// The PC client calls datacenter.kuwo.cn/d.c as an alternative to the
// r.s musicinfo endpoint. It returns jQuery-callback-wrapped JSON with
// song metadata including CDN tags and URLs.
//
// Captured request:
//
//	GET http://datacenter.kuwo.cn/d.c?cmd=query&ft=music&cmkey=mbox_minfo
//	    &resenc=utf8&ids=<rid>&callback=jQuery..._<ts>&_=<ts>
//
// Response example:
//
//	try { var jsondata={"rid":"579105436",
//	  "tag":"http://202.206.96.204/homepage/.../violin.wma",
//	  "approvesn":"","mvprovider":"","upload_user":"",
//	  "upload_time":""};
//	  jQuery..._<ts>(jsondata); }catch(e){jsonError(e)}

package p2p

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DataCenterHost is the music info datacenter.
const DataCenterHost = "http://datacenter.kuwo.cn"

// DataCenterRequest builds the GET URL for the d.c music info API.
func DataCenterRequest(rid uint64) string {
	return fmt.Sprintf(
		"/d.c?cmd=query&ft=music&cmkey=mbox_minfo&resenc=utf8&ids=%d",
		rid,
	)
}

// DataCenterEntry is one song entry in the d.c response.
type DataCenterEntry struct {
	RID          string `json:"rid"`
	Tag          string `json:"tag"`          // CDN URL
	ApproveSN    string `json:"approvesn"`
	MVProvider   string `json:"mvprovider"`
	UploadUser   string `json:"upload_user"`
	UploadTime   string `json:"upload_time"`
}

// DataCenterResponse contains parsed entries from d.c.
type DataCenterResponse struct {
	Entries []DataCenterEntry
	Raw     string
}

// DoDataCenter sends a d.c request and returns parsed entries.
func DoDataCenter(client *http.Client, rid uint64) (*DataCenterResponse, error) {
	url := DataCenterHost + DataCenterRequest(rid)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("datacenter request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("datacenter read: %w", err)
	}
	return ParseDataCenterBody(body)
}

// ParseDataCenterBody extracts JSON from a jQuery-callback wrapped response.
func ParseDataCenterBody(body []byte) (*DataCenterResponse, error) {
	text := string(body)
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no JSON found in datacenter response (%dB)", len(body))
	}
	jsonStr := text[start : end+1]

	var entries []DataCenterEntry
	if err := json.Unmarshal([]byte(jsonStr), &entries); err == nil {
		return &DataCenterResponse{Entries: entries, Raw: jsonStr}, nil
	}

	var single DataCenterEntry
	if err := json.Unmarshal([]byte(jsonStr), &single); err == nil {
		return &DataCenterResponse{Entries: []DataCenterEntry{single}, Raw: jsonStr}, nil
	}

	return nil, fmt.Errorf("cannot parse datacenter JSON: %s", jsonStr[:min(len(jsonStr), 200)])
}
// GetDownloadURL 从datacenter获取下载URL
func GetDownloadURL(client *http.Client, rid uint64) (string, error) {
	resp, err := DoDataCenter(client, rid)
	if err != nil {
		return "", err
	}
	
	if len(resp.Entries) > 0 {
		return resp.Entries[0].Tag, nil
	}
	return "", fmt.Errorf("no tag found for rid=%d", rid)
}
