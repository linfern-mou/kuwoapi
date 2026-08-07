package module

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"kuwoapi/util"
)

// Search 搜索接口
// 对应 kugoumusic 的 module/search.js
// 来源：KwMusicDLL.dll strings
// 端点：http://search.kuwo.cn/r.s?client=kt&all=%s&pn=0&rn=10&ft=music&newsearch=1
func Search(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	key := util.GetString(params, "key", "")
	if key == "" {
		return map[string]interface{}{"code": 400, "msg": "缺少参数 key"}, nil
	}

	pn := util.GetInt(params, "pn", 0)
	rn := util.GetInt(params, "rn", 10)

	u := fmt.Sprintf("http://search.kuwo.cn/r.s?client=kt&all=%s&pn=%d&rn=%d&ft=music&newsearch=1&cluster=0&strategy=2012&itemset=reco&ver=8.7.4.0&pcmp4=1",
		url.QueryEscape(key), pn, rn)

	resp, err := util.HTTPClient.Get(u)
	if err != nil {
		return nil, fmt.Errorf("搜索请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return map[string]interface{}{"code": 200, "data": string(body)}, nil
	}

	return map[string]interface{}{"code": 200, "data": result}, nil
}
