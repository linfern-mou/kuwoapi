/**
 * @fileoverview 酷我音乐虚拟用户接口
 *
 * 接口来源：default.zip 中 KwMusicDLL.dll strings 分析
 * 端点：http://pc.i.kuwo.cn/US_NEW/kuwo/vuser
 *
 * 服务标识（来源：KwMusicDLL.dll strings）：
 * - virtualsvr  虚拟用户服务
 * - GetVirtualUsrId  获取虚拟用户ID
 *
 * 响应字段（来源：KwMusicDLL.dll strings）：
 * - vSid  虚拟会话ID
 * - result / succ  结果
 * - errcode_%d;url_%s  错误码和URL
 *
 * 路由: /login/virtual
 *
 * @module login_virtual
 * @see REVERSE_SPEC.md 第三章第3.4节
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    uid: params?.uid || params?.cookie?.uid || '',
    sid: params?.sid || params?.cookie?.sid || '',
  };

  return useAxios({
    baseURL: 'http://pc.i.kuwo.cn',
    url: '/US_NEW/kuwo/vuser',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
