/**
 * @fileoverview 酷我音乐 API HTTP 请求封装
 *
 * 基于 default.zip 中 KwHttp.dll / KwHttpRequestMgr.dll 分析所得的请求逻辑。
 *
 * 请求方式：
 * - PC 客户端通过 KwHttp.dll 发送 HTTP/1.0 GET/POST 请求
 * - User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10
 * - 部分接口需要 sign 参数（由 KwLib.dll 的 Sig::CalcSign 生成，此处用 MD5 实现）
 *
 * 接口端点均来源于压缩包内 DLL/exe 的 strings 分析。
 *
 * @module request
 */

const axios = require('axios');
const { cryptoMd5 } = require('./crypto');
const { parseCookieString, randomString } = require('./util');
const { clientver } = require('./config.json');
const { resolveProxy } = require('./runtime');

// 签名盐值（来源于压缩包内 KwLib.dll 的 Sig::CalcSign 关联分析）
// PC 客户端签名逻辑：对请求参数做 MD5，sign 参数格式为 hex
const SIGN_SALT = 'yeelion';

/**
 * 生成请求签名 sign
 *
 * 酷我 PC 客户端 r.s 接口的签名方式：
 * 对 query string 做 MD5，附加固定盐值
 *
 * @param {string} query - 请求参数字符串（key=value&key=value 形式）
 * @returns {string} 32位十六进制签名
 */
const generateSign = (query) => {
  return cryptoMd5(`${query}${SIGN_SALT}`);
};

/**
 * 创建并发送 API 请求
 *
 * @param {Object} options - 请求选项
 * @param {string} options.url - 请求路径
 * @param {string} options.baseURL - 基础 URL（来源压缩包，如 http://search.kuwo.cn）
 * @param {string} [options.method] - HTTP 方法 GET/POST
 * @param {Object} [options.params] - 查询参数
 * @param {Object|Buffer} [options.data] - 请求体
 * @param {Object} [options.headers] - 自定义请求头
 * @param {Object} [options.cookie] - Cookie 对象
 * @param {boolean} [options.needSign] - 是否生成 sign 签名
 * @param {string} [options.ip] - 真实 IP（用于 IP 透传）
 * @returns {Promise<{status, body, cookie, headers}>}
 */
const createRequest = (options) => {
  return new Promise(async (resolve, reject) => {
    const ip = options?.realIP || options?.ip || '';
    const uid = options?.cookie?.uid || options?.cookie?.userid || '';
    const sid = options?.cookie?.sid || '';

    // 构建请求头（来源：KwHttpRequestMgr.dll 的 User-Agent）
    const headers = {
      'User-Agent':
        'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10',
      Accept: '*/*',
    };

    if (ip) {
      headers['X-Real-IP'] = ip;
      headers['X-Forwarded-For'] = ip;
    }

    // 合并自定义头
    Object.assign(headers, options?.headers || {});

    // 构建查询参数
    let params = Object.assign({}, options?.params || {});

    // 注入客户端版本（来源：config.ini modulesver=8.7.4.0）
    if (!params.ver && options?.injectVer !== false) {
      params.ver = clientver;
    }

    // 生成签名（来源：KwLib.dll Sig::CalcSign，stype=geturl 等接口需要）
    if (options?.needSign && !params.sign) {
      const queryStr = Object.keys(params)
        .sort()
        .map((k) => `${k}=${params[k]}`)
        .join('&');
      params.sign = generateSign(queryStr);
    }

    // 注入 uid/sid（部分接口需要，来源：op=submit 等）
    if (uid && !params.uid) params.uid = uid;
    if (sid && !params.sid) params.sid = sid;

    const requestOptions = {
      method: options.method || 'GET',
      baseURL: options?.baseURL,
      url: options.url,
      params,
      headers,
      withCredentials: true,
      responseType: options.responseType || 'text',
      timeout: 10000,
    };

    // 请求体
    if (options.data) {
      if (Buffer.isBuffer(options.data)) {
        requestOptions.data = options.data;
      } else if (typeof options.data === 'object') {
        requestOptions.data = options.data;
      } else {
        requestOptions.data = options.data;
      }
    }

    // 代理配置
    const proxyConfig = resolveProxy();
    if (proxyConfig) {
      requestOptions.proxy = proxyConfig;
    }

    // 发送请求
    const answer = { status: 500, body: {}, cookie: [], headers: {} };
    try {
      const response = await axios(requestOptions);

      // 解析 Set-Cookie
      answer.cookie = (response.headers['set-cookie'] || []).map((x) => parseCookieString(x));
      answer.headers = response.headers;

      // 解析响应体
      const body = response.data;
      if (typeof body === 'string') {
        try {
          answer.body = JSON.parse(body);
        } catch (e) {
          answer.body = body;
        }
      } else {
        answer.body = body;
      }

      answer.status = response.status;
      resolve(answer);
    } catch (e) {
      answer.status = e.response?.status || 502;
      answer.body = { code: answer.status, msg: e.message || 'request error' };
      reject(answer);
    }
  });
};

module.exports = { createRequest, generateSign };
