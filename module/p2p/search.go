package p2p

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// DhjssSearchResponse dhjss搜索响应结构
type DhjssSearchResponse struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Fartist     string `json:"FARTIST"`
	Aartist     string `json:"AARTIST"`
	Intro       string `json:"intro"`
	PlayCnt     string `json:"playcnt_t"`
	Pic         string `json:"pic"`
	RadioID     string `json:"radioid"`
	RadioName   string `json:"radioname"`
	PageURL     string `json:"pageurl"`
	SongNum     string `json:"songnum"`
	MvNum       string `json:"mvnum"`
	AlbumNum    string `json:"albumnum"`
	Song        []struct {
		Mvname string `json:"mvname"`
		Name   string `json:"name"`
		Pic    string `json:"pic"`
		Artist string `json:"artist"`
		Album  string `json:"album"`
		Id     string `json:"id"`
		Pid    string `json:"pid"`
	} `json:"song"`
	Album []struct {
		Name   string `json:"name"`
		Artist string `json:"artist"`
		Id     string `json:"id"`
	} `json:"album"`
}

// DecodeGBK 将疑似GBK编码的JSON字符串转换为UTF-8
// 当JSON解析失败时，尝试替换不可解析字符
func DecodeGBK(raw string) (string, error) {
	// 如果已经是有效的UTF-8，直接返回
	if utf8.ValidString(raw) {
		return raw, nil
	}
	// 替换无效UTF-8字符为占位符
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if r == utf8.RuneError {
			b.WriteString("?")
		} else {
			b.WriteRune(r)
		}
	}
	return b.String(), nil
}

// DhjssSearch 执行dhjss搜索（主搜索入口）
func DhjssSearch(keyword string) ([]DhjssSearchResponse, error) {
	baseURL := "http://dhjss.kuwo.cn/s.c"
	params := url.Values{}
	params.Set("all", keyword)
	params.Set("tset", "artist,album,playlist")
	params.Set("multires", "1")

	reqURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	client := &http.Client{}
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "KuwoMusicPC/8.7.4.0_BDS")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 65536)
	n, err := resp.Body.Read(buf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("read response: %w", err)
	}

	data := string(buf[:n])
	
	// 解析JSON（可能包含GBK编码的中文字符）
	var results []DhjssSearchResponse
	if err := json.Unmarshal([]byte(data), &results); err != nil {
		// 尝试清理后再解析
		cleaned, _ := DecodeGBK(data)
		if err2 := json.Unmarshal([]byte(cleaned), &results); err2 != nil {
			return nil, fmt.Errorf("parse json: %v (raw: %s)", err2, data[:min(len(data), 100)])
		}
	}

	return results, nil
}

// JiucuoCorrect 搜索纠错
func JiucuoCorrect(keyword string) (string, error) {
	baseURL := "http://jiucuo.search.kuwo.cn/correct.s"
	params := url.Values{}
	params.Set("key", keyword)

	reqURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	client := &http.Client{}
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "KuwoMusicPC/8.7.4.0_BDS")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil && n == 0 {
		return "", fmt.Errorf("read response: %w", err)
	}

	return string(buf[:n]), nil
}

// SkeylistHot 获取热搜词
func SkeylistHot() (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://skeylist.kuwo.cn/searchkey/searchkey.txt", nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "KuwoMusicPC/8.7.4.0_BDS")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 8192)
	n, err := resp.Body.Read(buf)
	if err != nil && n == 0 {
		return "", fmt.Errorf("read response: %w", err)
	}

	return string(buf[:n]), nil
}
