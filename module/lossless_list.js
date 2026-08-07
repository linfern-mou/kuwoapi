/**
 * @fileoverview 酷我音乐无损列表接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：http://misc.service.kuwo.cn/lossless/list
 *
 * 路由: /lossless/list
 *
 * @module lossless_list
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    uid: params?.uid || params?.cookie?.uid || '',
  };

  return useAxios({
    baseURL: 'http://misc.service.kuwo.cn',
    url: '/lossless/list',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
