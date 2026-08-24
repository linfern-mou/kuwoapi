package module

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

	// 提取每首歌的 P2P 签名（param 字段，来源 channel_bang.js saveMusicInfo）
	if ml, ok := result["musiclist"].([]interface{}); ok {
		for _, c := range ml {
			if m, ok := c.(map[string]interface{}); ok {
				chain, _ := m["param"].(string)
				mergeParam(m, chain)
			}
		}
	}

	return map[string]interface{}{"code": 200, "data": result}, nil
}

// RankList 榜单列表接口
// 来源：channel_bang.js（排行榜频道页左侧分类树）
// 端点：http://qukudata.kuwo.cn/q.k?op=query&cont=tree&node=2&pn=0&rn=20&fmt=json&src=mbox&level=2
// 客户端逻辑：pc_extend 含 NOTSHOWPC2015 的项在 PC 隐藏；
//   pc_extend 中 BDTYPE-{分组}-{oid} 决定分组展示，缺省为「特色榜」；
//   sourceid 17/16/93 为特殊介绍项（客户端仅取 intro 文本）
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

	children, _ := result["child"].([]interface{})
	groups := make(map[string][]map[string]interface{})
	order := []string{}
	list := make([]map[string]interface{}, 0, len(children))
	for _, c := range children {
		item, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		ext, _ := item["pc_extend"].(string)
		if strings.Contains(ext, "NOTSHOWPC2015") {
			continue
		}
		sourceid := fmt.Sprintf("%v", item["sourceid"])

		group := ""
		hot := false
		for _, kv := range strings.Split(ext, "|") {
			switch {
			case kv == "HOT":
				hot = true
			case strings.HasPrefix(kv, "BDTYPE"):
				parts := strings.SplitN(kv, "-", 3)
				if len(parts) >= 2 {
					group = parts[1]
				}
			}
		}
		if group == "" && sourceid != "17" && sourceid != "16" && sourceid != "93" {
			group = "特色榜"
		}

		entry := map[string]interface{}{
			"id":        sourceid,
			"name":      item["name"],
			"pic":       item["pic"],
			"info":      item["info"],
			"intro":     item["intro"],
			"listen":    item["listen"],
			"isnew":     item["isnew"],
			"newcnt":    item["newcnt"],
			"hot":       hot,
			"special":   sourceid == "17" || sourceid == "16" || sourceid == "93",
		}
		list = append(list, entry)

		if group != "" {
			if _, seen := groups[group]; !seen {
				order = append(order, group)
			}
			groups[group] = append(groups[group], entry)
		}
	}

	groupedList := make([]map[string]interface{}, 0, len(order))
	for _, g := range order {
		groupedList = append(groupedList, map[string]interface{}{
			"group": g,
			"list":  groups[g],
		})
	}

	return map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"name":   result["name"],
			"count":  len(list),
			"list":   list,
			"groups": groupedList,
		},
	}, nil
}
