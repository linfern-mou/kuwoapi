/**
 * @fileoverview 酷我音乐搜索接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：http://search.kuwo.cn/r.s?client=kt&all=%s&pn=%d&rn=%d&ft=music&newsearch=1&cluster=0&strategy=2012&itemset=reco&ver=%s&pcmp4=1
 *
 * 路由: /search
 *
 * @module search
 */

const { clientver } = require('../util/config.json');

module.exports = (params, useAxios) => {
  const dataMap = {
    client: 'kt',
    all: params?.key || params?.all || '',
    pn: params?.pn || 0,
    rn: params?.rn || 10,
    ft: 'music',
    newsearch: 1,
    cluster: 0,
    strategy: 2012,
    itemset: 'reco',
    ver: params?.ver || clientver,
    pcmp4: 1,
  };

  return useAxios({
    baseURL: 'http://search.kuwo.cn',
    url: '/r.s',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
