package module

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"kuwoapi/util"
)

// Search 搜索接口
// 来源：KwMusicDLL.dll strings
// URL模板：http://search.kuwo.cn/r.s?client=kt&all=%s%%20%s&pn=0&rn=10&ft=music&newsearch=1&cluster=0&strategy=2012&itemset=reco&ver=%s&mp4=1
// 响应格式：8字节头 + zlib压缩的KV文本（当 result=zip 时）或纯KV文本
func Search(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	key := util.GetString(params, "key", "")
	if key == "" {
		return map[string]interface{}{"code": 400, "msg": "缺少参数 key"}, nil
	}

	pn := util.GetInt(params, "pn", 0)
	rn := util.GetInt(params, "rn", 10)

	// URL 来源：KwMusicDLL.dll strings
	// http://search.kuwo.cn/r.s?client=kt&all=%s%%20%s&pn=0&rn=10&ft=music&newsearch=1&cluster=0&strategy=2012&itemset=reco&ver=%s&mp4=1
	u := fmt.Sprintf("http://search.kuwo.cn/r.s?client=kt&all=%s&pn=%d&rn=%d&ft=music&newsearch=1&cluster=0&strategy=2012&itemset=reco&ver=8.7.4.0&pcmp4=1",
		url.QueryEscape(key), pn, rn)

	req, _ := http.NewRequest("GET", u, nil)
	// 请求头来源：KwHttpRequestMgr.dll strings
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10")
	req.Header.Set("Accept", "application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.8")
	req.Header.Set("Accept-Charset", "GBK,utf-8;q=0.7,*;q=0.3")
	req.Header.Set("Accept-encoding", "gzip, deflate")
	req.Header.Set("Connection", "Close")

	resp, err := util.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("搜索请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 响应格式判断
	var text string
	if len(body) > 8 && body[8] == 0x78 {
		// 8字节头 + zlib 压缩
		reader, err := zlib.NewReader(bytes.NewReader(body[8:]))
		if err != nil {
			text = string(body)
		} else {
			defer reader.Close()
			decompressed, err := io.ReadAll(reader)
			if err != nil {
				text = string(body)
			} else {
				text = string(decompressed)
			}
		}
	} else {
		// 纯文本
		text = string(body)
	}

	// 解析 KV 文本
	// 来源：KwMusicDLL.dll strings - SONGNAME=, ARTIST=, ALBUM=, MUSICRID=, FORMATS=
	songs := parseSearchKV(text)

	return map[string]interface{}{"code": 200, "data": songs}, nil
}

// parseSearchKV 解析搜索响应 KV 文本
// 来源：KwMusicDLL.dll strings
func parseSearchKV(text string) []map[string]interface{} {
	var songs []map[string]interface{}
	var current map[string]interface{}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			if current != nil && len(current) > 0 {
				songs = append(songs, current)
				current = nil
			}
			continue
		}

		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		// 来源：KwMusicDLL.dll strings
		switch key {
		case "SONGNAME":
			if current != nil && len(current) > 0 {
				songs = append(songs, current)
			}
			current = map[string]interface{}{"name": val}
		case "ARTIST":
			if current != nil {
				current["artist"] = val
			}
		case "ALBUM":
			if current != nil {
				current["album"] = val
			}
		case "MUSICRID":
			if current != nil {
				current["rid"] = val
			}
		case "ALBUMID":
			if current != nil {
				current["albumid"] = val
			}
		case "ARTISTID":
			if current != nil {
				current["artistid"] = val
			}
		case "FORMATS":
			if current != nil {
				current["formats"] = val
			}
		case "PAY":
			if current != nil {
				current["pay"] = val
			}
		case "DURATION":
			if current != nil {
				current["duration"] = val
			}
		case "MP3RID":
			if current != nil {
				current["mp3rid"] = val
			}
		case "MKVRID", "MVRID":
			if current != nil {
				current["mvrid"] = val
			}
		}
	}

	if current != nil && len(current) > 0 {
		songs = append(songs, current)
	}

	return songs
}
