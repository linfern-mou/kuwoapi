/**
 * @fileoverview 酷我音乐账号登录接口
 *
 * 接口来源：default.zip 中 KwMusicDLL.dll strings 分析
 *
 * 端点：http://pc.i.kuwo.cn/US_NEW/kuwo/login_kw
 *
 * 登录方式（来源：KwMusicDLL.dll）：
 * - kuwologin  酷我账号登录（用户名+密码）
 * - qqlogin    QQ登录
 * - wblogin    微博登录
 * - weixinlogin 微信登录
 *
 * 请求参数模板（来源：KwMusicDLL.dll strings）：
 *   username=%s&password=%s&from=pc&dev_id=%s
 *   &devType=devType&devResolution=devResolution
 *   &src=mbox&sx=%s&version=%s&dev_name=%s
 *
 * 加密相关（来源：KwMusicDLL.dll strings）：
 * - encryptlogin 标识确认存在（加密登录）
 * - kw@#d09b 盐值确认存在（登录参数区域）
 * - Entrypt::Encrypt 函数确认存在
 *   [算法未确认] 密码具体加密方式未知，禁止推测
 *
 * 路由: /login
 *
 * @module login
 * @see REVERSE_SPEC.md 第三章第3.4节
 */

const { clientver } = require('../util/config.json');

module.exports = (params, useAxios) => {
  const dataMap = {
    username: params?.username || params?.uname || '',
    password: params?.password || params?.pwd || '',
    from: 'pc',
    dev_id: params?.dev_id || '',
    devType: params?.devType || 'devType',
    devResolution: params?.devResolution || 'devResolution',
    src: 'mbox',
    sx: params?.sx || '',
    version: params?.version || clientver,
    dev_name: params?.dev_name || '',
  };

  // 第三方登录类型（来源：KwMusicDLL.dll strings: qqlogin/wblogin/weixinlogin）
  if (params?.loginType) {
    dataMap.loginType = params.loginType;
  }

  return useAxios({
    baseURL: 'http://pc.i.kuwo.cn',
    url: '/US_NEW/kuwo/login_kw',
    method: 'POST',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
