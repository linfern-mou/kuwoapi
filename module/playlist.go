package module

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"

	"kuwoapi/util"
)

// PlaylistRcm 个性化推荐歌单
// 来源：PC 客户端首页「推荐歌单」板块 (html/webdata/netsong/js/index.js getRcmPlaylistData)
// 端点：http://rcm.kuwo.cn/rec.s?cmd=rcm_keyword_playlist&uid=&devid=&platform=pc
// 说明：需携带 User-Agent，否则被 openresty 302；playlist 少于等于 4 个时客户端会隐藏板块
func PlaylistRcm(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	uid := util.GetString(params, "uid", "123434546")
	devid := util.GetString(params, "devid", "19976128")
	limit := util.GetInt(params, "limit", 10)

	u := fmt.Sprintf("http://rcm.kuwo.cn/rec.s?cmd=rcm_keyword_playlist&uid=%s&devid=%s&platform=pc&t=%d",
		uid, devid, rand.Int63())

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Referer", "http://www.kuwo.cn/")

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
		Keyword  string                   `json:"keyword"`
		Playlist []map[string]interface{} `json:"playlist"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return map[string]interface{}{"code": 500, "msg": "推荐歌单响应解析失败"}, nil
	}

	list := make([]map[string]interface{}, 0, len(raw.Playlist))
	for _, p := range raw.Playlist {
		if len(list) >= limit {
			break
		}
		playcnt, _ := strconv.ParseInt(toString(p["playcnt"]), 10, 64)
		list = append(list, map[string]interface{}{
			"id":       p["sourceid"],
			"name":     p["disname"],
			"pic":      p["pic"],
			"playcnt":  playcnt,
			"lossless": toString(p["extend"]) != "0",
			"traceid":  p["traceid"],
		})
	}

	return map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"uid":     uid,
			"devid":   devid,
			"keyword": raw.Keyword,
			"count":   len(list),
			"list":    list,
		},
	}, nil
}

func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
