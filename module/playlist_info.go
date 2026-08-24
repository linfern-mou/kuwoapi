package module

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"kuwoapi/util"
)

// PlaylistInfo 歌单详情
// 来源：PC 客户端歌单详情页 (html/webdata/netsong/js/content_gedan.js getSomeData)
// 端点：http://nplserver.kuwo.cn/pl.svc?op=getlistinfo&pid=&pn=&rn=&encode=utf-8&keyset=pl2012&identity=kuwo&pcmp4=1
// 说明：vipver=1 必带（客户端 getChargeURL 逻辑），缺失时部分歌单 musiclist 为空；
//       ttime 实测可省略
func PlaylistInfo(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	pid := util.GetString(params, "id", "")
	if pid == "" {
		return nil, fmt.Errorf("缺少歌单 id")
	}
	pn := util.GetInt(params, "pn", 0)
	rn := util.GetInt(params, "rn", 100)

	u := fmt.Sprintf("http://nplserver.kuwo.cn/pl.svc?op=getlistinfo&pid=%s&pn=%d&rn=%d&encode=utf-8&keyset=pl2012&identity=kuwo&pcmp4=1&vipver=1",
		pid, pn, rn)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := util.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var raw struct {
		ID        int                      `json:"id"`
		Title     string                   `json:"title"`
		Pic       string                   `json:"pic"`
		Info      string                   `json:"info"`
		Uname     string                   `json:"uname"`
		Tag       string                   `json:"tag"`
		Total     int                      `json:"total"`
		PN        int                      `json:"pn"`
		MusicList []map[string]interface{} `json:"musiclist"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return map[string]interface{}{"code": 500, "msg": "歌单详情响应解析失败"}, nil
	}

	list := make([]map[string]interface{}, 0, len(raw.MusicList))
	for _, m := range raw.MusicList {
		entry := map[string]interface{}{
			"rid":        anyToString(m["id"]),
			"name":       m["name"],
			"artist":     m["artist"],
			"artistid":   m["artistid"],
			"album":      m["album"],
			"albumid":    m["albumid"],
			"albumpic":   m["albumpic"],
			"duration":   anyToInt(m["duration"]),
			"formats":    m["formats"],
			"pay":        anyToInt(m["pay"]),
			"lossless":   containsFLAC(anyToString(m["MINFO"])),
			"isdownload": anyToString(m["isdownload"]) == "0",
		}
		// P2P 签名（params 字段，来源 content_gedan.js -> saveMusicInfo）
		chain, _ := m["params"].(string)
		mergeParam(entry, chain)
		list = append(list, entry)
	}

	title := raw.Title
	return map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"id":    raw.ID,
			"title": title,
			"pic":   raw.Pic,
			"info":  raw.Info,
			"uname": raw.Uname,
			"tag":   raw.Tag,
			"total": raw.Total,
			"pn":    raw.PN,
			"list":  list,
		},
	}, nil
}

func anyToString(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	case float64:
		return strconv.FormatInt(int64(s), 10)
	default:
		return ""
	}
}

func anyToInt(v interface{}) int64 {
	n, _ := strconv.ParseInt(anyToString(v), 10, 64)
	return n
}

func containsFLAC(minfo string) bool {
	for _, seg := range splitSegs(minfo) {
		if seg == "format:flac" {
			return true
		}
	}
	return false
}

func splitSegs(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ';' || s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
