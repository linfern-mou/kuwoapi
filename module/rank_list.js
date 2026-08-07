/**
 * @fileoverview 酷我音乐曲库分类树接口（含榜单列表）
 *
 * 接口来源：default.zip 中 html/webdata/netsong/js/channel_bang.js 与 content_bang.js
 * 端点：http://qukudata.kuwo.cn/q.k
 *
 * URL 模板（压缩包确认）：
 *   1. 分类树：
 *      http://qukudata.kuwo.cn/q.k?op=query&cont=tree&node=2&pn=0&rn=20&fmt=json&src=mbox&level=2
 *   2. 节点信息（榜单简介）：
 *      http://qukudata.kuwo.cn/q.k?op=query&cont=ninfo&node={sourceid}&pn=0&rn=10&fmt=json&src=mbox
 *
 * 参数说明：
 * | 参数 | 值/格式 | 说明 |
 * | op | query | 固定值 |
 * | cont | tree / ninfo | tree=分类树，ninfo=节点信息 |
 * | node | %d | 节点 ID（cont=tree 时为 2，cont=ninfo 时为 sourceid） |
 * | pn | 0 | 页码 |
 * | rn | %d | 每页数量（tree=20，ninfo=10） |
 * | fmt | json | 返回格式 |
 * | src | mbox | 固定值 |
 * | level | 2 | 树层级（cont=tree 时使用） |
 *
 * 已知 sourceid（来源：channel_bang.html c-sourceid 属性）：
 * | sourceid | 对应榜单 |
 * | 26 | 酷我热歌榜 |
 * | 25 | 酷我新歌榜 |
 * | 80358 | 酷我飙升榜 |
 *
 * 路由: /rank/list
 *
 * @module rank_list
 * @see REVERSE_SPEC.md 第三章第3.11节
 */

module.exports = (params, useAxios) => {
  // cont=ninfo 时取节点信息，否则默认 cont=tree 取分类树
  const cont = params?.cont || 'tree';

  const dataMap = {
    op: 'query',
    cont,
    node: params?.node || (cont === 'tree' ? 2 : 0),
    pn: params?.pn || 0,
    rn: params?.rn || (cont === 'tree' ? 20 : 10),
    fmt: 'json',
    src: 'mbox',
  };

  if (cont === 'tree') {
    dataMap.level = params?.level || 2;
  }

  return useAxios({
    baseURL: 'http://qukudata.kuwo.cn',
    url: '/q.k',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
