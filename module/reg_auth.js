/**
 * @fileoverview 酷我音乐注册验证接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * URL 模板：%s/regsvr.auth?%d&%s
 * 端点：http://reg.kuwo.cn/regsvr.auth?{时间戳}&{uid}
 *
 * 参数说明（来源：DLL strings）：
 * - %d  时间戳（Unix 时间）
 * - %s  uid（用户ID）
 *
 * 路由: /reg/auth
 *
 * @module reg_auth
 * @see REVERSE_SPEC.md 第三章第3.4节
 */

module.exports = (params, useAxios) => {
  const ts = Math.floor(Date.now() / 1000);
  const uid = params?.uid || '';

  return useAxios({
    baseURL: 'http://reg.kuwo.cn',
    url: `/regsvr.auth?${ts}&${uid}`,
    method: 'GET',
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
