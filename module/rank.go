package module

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"kuwoapi/util"
)

// Rank 排行榜内容接口
// 来源：channel_bang.js + content_bang.js
// 端点：https://kbangserver.kuwo.cn/ksong.s
func Rank(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	id := util.GetString(params, "id", "16")
	pn := util.GetInt(params, "pn", 0)
	rn := util.GetInt(params, "rn", 200)

	u := fmt.Sprintf("https://kbangserver.kuwo.cn/ksong.s?from=pc&fmt=json&type=bang&data=content&id=%s&pn=%d&rn=%d&isbang=1&show_copyright_off=0&pcmp4=1&t=%d",
		id, pn, rn, util.GetInt(params, "t", 0))

	resp, err := util.HTTPClient.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return map[string]interface{}{"code": 200, "data": string(body)}, nil
	}
	return map[string]interface{}{"code": 200, "data": result}, nil
}

// RankList 榜单列表接口
// 来源：channel_bang.js
// 端点：http://qukudata.kuwo.cn/q.k
func RankList(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	u := "http://qukudata.kuwo.cn/q.k?op=query&cont=tree&node=2&pn=0&rn=20&fmt=json&src=mbox&level=2"

	resp, err := util.HTTPClient.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return map[string]interface{}{"code": 200, "data": string(body)}, nil
	}
	return map[string]interface{}{"code": 200, "data": result}, nil
}
