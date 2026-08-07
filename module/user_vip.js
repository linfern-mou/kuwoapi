/**
 * @fileoverview 酷我音乐 VIP 信息接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：http://vip1.kuwo.cn/vip/v2/user/vip
 *
 * 路由: /user/vip
 *
 * @module user_vip
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    uid: params?.uid || params?.cookie?.uid || '',
  };

  return useAxios({
    baseURL: 'http://vip1.kuwo.cn',
    url: '/vip/v2/user/vip',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
