package p2p

import (
	"fmt"
	"strings"
)

// DownloadInfo 下载信息
type DownloadInfo struct {
	RID     string `json:"rid"`
	Name    string `json:"name"`
	Artist  string `json:"artist"`
	URL     string `json:"url"`
	Format  string `json:"format"`
	Token   string `json:"token"`
	Quality string `json:"quality"`
}

// BestQuality 从MINFO解析中获取最佳音质
func BestQuality(song MusicPaySong) *MusicPayQuality {
	qualities := ParseMINFO(song.MINFO)
	if len(qualities) == 0 {
		return nil
	}
	// 优先FLAC
	for i := range qualities {
		if strings.Contains(strings.ToUpper(qualities[i].Format), "FLAC") {
			return &qualities[i]
		}
	}
	return &qualities[0]
}

// ParseDownloadURL 从raw audio数据解析下载URL
func ParseDownloadURL(raw map[string]interface{}) string {
	sourceID, _ := raw["p2p_audiosourceid"].(string)
	if sourceID == "" {
		return ""
	}
	
	// 格式: 254547612 + 30106 + trackmedia + F000002cjEhn44AZ3y + ext
	const prefixLen = 9
	
	if !strings.Contains(sourceID, "trackmedia") {
		return ""
	}
	
	idx := strings.Index(sourceID, "trackmedia")
	if idx < prefixLen {
		return ""
	}
	
	resID := sourceID[prefixLen:idx]
	filename := sourceID[idx+len("trackmedia"):]
	
	// 从fmt推断扩展名
	fmtStr, _ := raw["fmt"].(string)
	ext := getExtFromFmt(fmtStr)
	cdn := "kw-lw.kuwo.cn"
	
	return fmt.Sprintf("http://%s/resource/%s/trackmedia/%s.%s?source=pc_player.%s",
		cdn, resID, filename, ext, ext)
}

// getExtFromFmt 根据格式字符串获取扩展名
func getExtFromFmt(fmtStr string) string {
	switch {
	case strings.Contains(strings.ToUpper(fmtStr), "FLAC"):
		return "flac"
	case strings.Contains(strings.ToUpper(fmtStr), "MP3"):
		return "mp3"
	case strings.Contains(strings.ToUpper(fmtStr), "OGG"):
		return "ogg"
	case strings.Contains(strings.ToUpper(fmtStr), "WMA"):
		return "wma"
	case strings.Contains(strings.ToUpper(fmtStr), "AAC"):
		return "m4a"
	default:
		return "mp3"
	}
}
