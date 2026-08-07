/**
 * @fileoverview 酷我音乐排行榜内容接口
 *
 * 接口来源：default.zip 中 html/webdata/netsong/js/channel_bang.js 与 content_bang.js
 * 端点：https://kbangserver.kuwo.cn/ksong.s
 *
 * URL 模板（压缩包确认）：
 *   https://kbangserver.kuwo.cn/ksong.s?from=pc&fmt=json&type=bang&data=content
 *     &id={bangid}&pn={pn}&rn={rn}&isbang=1&show_copyright_off=0&pcmp4=1&bangid={bangid}
 *     &t={timestamp}
 *
 * 参数说明：
 * | 参数 | 值/格式 | 说明 |
 * | from | pc | 固定值 |
 * | fmt | json | 返回格式 |
 * | type | bang | 固定值 |
 * | data | content | 取榜单内容 |
 * | id | %d | 榜单 ID（16=热歌榜, 17=新歌榜, 93=飙升榜, 132=亚洲榜） |
 * | pn | %d | 页码，从 0 开始 |
 * | rn | %d | 每页数量（频道页 20，内容页 200） |
 * | isbang | 1 | 固定值 |
 * | show_copyright_off | 0 | 固定值 |
 * | pcmp4 | 1 | 固定值 |
 * | bangid | %d | 子榜单 ID（可选） |
 * | t | %d | 时间戳，防缓存 |
 *
 * 已知榜单 ID（来源：channel_bang.html c-id 属性）：
 * | id | sourceid | 名称 |
 * | 16 | 26 | 酷我热歌榜 |
 * | 17 | 25 | 酷我新歌榜 |
 * | 93 | 80358 | 酷我飙升榜 |
 * | 132 | -99 | 酷音乐亚洲排行榜 |
 *
 * 路由: /rank
 *
 * @module rank
 * @see REVERSE_SPEC.md 第三章第3.11节
 */

module.exports = (params, useAxios) => {
  const id = params?.id || params?.bangid || 16;

  const dataMap = {
    from: 'pc',
    fmt: 'json',
    type: 'bang',
    data: 'content',
    id,
    pn: params?.pn || 0,
    rn: params?.rn || 200,
    isbang: 1,
    show_copyright_off: 0,
    pcmp4: 1,
    t: Date.now(),
  };

  // bangid 子榜单（来源：content_bang.js 第 53、146 行）
  if (params?.bangid) {
    dataMap.bangid = params.bangid;
  }

  return useAxios({
    baseURL: 'https://kbangserver.kuwo.cn',
    url: '/ksong.s',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
