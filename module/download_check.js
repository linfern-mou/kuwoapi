/**
 * @fileoverview 酷我音乐下载状态检查接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：?op=ucheck&fmt=km&client=kwmusic&compress=no&bigid=1&pcmp4=1&encode=utf-8&
 *
 * 路由: /download/check
 *
 * @module download_check
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    op: 'ucheck',
    fmt: params?.fmt || 'km',
    client: 'kwmusic',
    compress: params?.compress || 'no',
    bigid: 1,
    pcmp4: 1,
    encode: 'utf-8',
  };

  return useAxios({
    baseURL: 'http://cldserver.kuwo.cn',
    url: '/c.s',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
