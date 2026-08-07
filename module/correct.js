/**
 * @fileoverview 酷我音乐数据纠错接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：http://jiucuo.search.kuwo.cn/correct.s?key=%s
 *
 * 路由: /correct
 *
 * @module correct
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    key: params?.key || '',
  };

  return useAxios({
    baseURL: 'http://jiucuo.search.kuwo.cn',
    url: '/correct.s',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
