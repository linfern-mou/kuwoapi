/**
 * @fileoverview 酷我音乐 API HTTP 请求封装
 *
 * 严格遵守 REVERSE_SPEC.md 约束：
 * - 接口端点必须来自压缩包 strings 分析（见文档第三章）
 * - 签名算法 [未确认]，需要签名的接口标注但不实现签名逻辑
 *
 * 请求方式（来源：压缩包 KwHttp.dll / KwHttpRequestMgr.dll 分析）：
 * - PC 客户端通过 KwHttp.dll 发送 HTTP GET/POST 请求
 *
 * @module request
 * @see REVERSE_SPEC.md 第三章
 */

const axios = require('axios');
const { parseCookieString } = require('./util');
const { clientver } = require('./config.json');
const { resolveProxy } = require('./runtime');
const { generateSign } = require('./helper');

/**
 * 创建并发送 API 请求
 *
 * @param {Object} options - 请求选项
 * @param {string} options.url - 请求路径
 * @param {string} options.baseURL - 基础 URL（来源压缩包，如 http://search.kuwo.cn）
 * @param {string} [options.method] - HTTP 方法 GET/POST
 * @param {Object} [options.params] - 查询参数（来源压缩包 %s 模板）
 * @param {Object|Buffer} [options.data] - 请求体
 * @param {Object} [options.headers] - 自定义请求头
 * @param {Object} [options.cookie] - Cookie 对象
 * @param {boolean} [options.needSign] - 是否需要 sign 签名
 *   ⚠️ 需要签名的接口（stype=geturl 等）设置此选项，
 *   但签名算法 [未确认]，会抛出错误提示需要人工逆向
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

    Object.assign(headers, options?.headers || {});

    // 构建查询参数（来源：压缩包 %s 格式化模板）
    let params = Object.assign({}, options?.params || {});

    // 注入客户端版本（来源：config.ini modulesver=8.7.4.0）
    if (!params.ver && options?.injectVer !== false) {
      params.ver = clientver;
    }

    // 签名处理（来源：压缩包 stype=geturl&sign=%s 等接口需要 sign）
    // ⚠️ [算法未确认] Sig::CalcSign 算法未逆向，调用 generateSign 会抛错
    if (options?.needSign && !params.sign) {
      try {
        params.sign = generateSign(params);
      } catch (e) {
        // 签名算法未确认，拒绝请求并返回明确错误
        reject({
          status: 501,
          body: {
            code: 501,
            msg: e.message,
          },
          cookie: [],
          headers: {},
        });
        return;
      }
    }

    // 注入 uid/sid（来源：op=submit 等接口参数模板）
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

    if (options.data) {
      requestOptions.data = options.data;
    }

    const proxyConfig = resolveProxy();
    if (proxyConfig) {
      requestOptions.proxy = proxyConfig;
    }

    const answer = { status: 500, body: {}, cookie: [], headers: {} };
    try {
      const response = await axios(requestOptions);

      answer.cookie = (response.headers['set-cookie'] || []).map((x) => parseCookieString(x));
      answer.headers = response.headers;

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

module.exports = { createRequest };
