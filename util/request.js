/**
 * @fileoverview 酷我音乐 API HTTP 请求封装
 *
 * 本模块是所有 API 请求的底层发送函数，负责：
 * 1. 注入网页端默认参数（plat、httpsStatus、reqId）
 * 2. 生成 Secret 请求头（基于 Hm_Iuvt cookie 的 LCG+XOR 加密）
 * 3. 配置请求头（User-Agent、Cookie、Referer、CSRF 等）
 * 4. 发送 HTTP 请求（通过 axios）
 * 5. 处理响应（解析 Cookie、错误处理）
 *
 * @module request
 */

const axios = require('axios');
const { parseCookieString } = require('./util');
const { generateKuwoSecret, generateReqId } = require('./crypto');
const { baseURL, hmCookie } = require('./config.json');
const { resolveProxy } = require('./runtime');

/**
 * 从 cookie 对象构建 cookie 字符串
 */
function buildCookieString(cookieObj) {
  return Object.entries(cookieObj || {})
    .map(([k, v]) => `${k}=${v}`)
    .join('; ');
}

/**
 * 创建并发送 API 请求
 *
 * @param {Object} options - 请求选项
 * @param {string} options.url - 请求路径（相对或绝对）
 * @param {string} options.method - HTTP 方法
 * @param {Object} options.params - URL 查询参数
 * @param {Object|Buffer} options.data - 请求体
 * @param {Object} options.headers - 自定义请求头
 * @param {Object} options.cookie - Cookie 对象
 * @param {boolean} options.needSecret - 是否需要 Secret 头（默认 true）
 * @param {boolean} options.needReqId - 是否需要 reqId 参数（默认 true）
 * @param {string} options.baseURL - 基础 URL
 * @param {string} options.ip - 真实 IP（透传）
 * @returns {Promise<{status, body, cookie, headers}>}
 */
const createRequest = (options) => {
  return new Promise(async (resolve, reject) => {
    const ip = options?.realIP || options?.ip || '';
    const cookie = options?.cookie || {};
    const useBaseURL = options?.baseURL || baseURL;

    // 生成或复用 reqId
    const reqId = options?.params?.reqId || generateReqId();

    // 合并默认查询参数
    const defaultParams = {
      httpsStatus: 1,
      reqId,
      plat: 'web_www',
    };

    const params = Object.assign(
      {},
      options?.clearDefaultParams ? {} : defaultParams,
      options?.params || {}
    );

    // 构建 cookie：注入 Hm_Iuvt cookie（如果不存在则设为空）
    const hmKey = hmCookie;
    if (!(hmKey in cookie)) {
      cookie[hmKey] = cookie[hmKey] || '';
    }
    const cookieString = buildCookieString(cookie);

    // 构建请求头
    const headers = Object.assign(
      {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        Referer: 'https://kuwo.cn/',
        Origin: 'https://kuwo.cn',
        'Content-Type': 'application/json',
        Cookie: cookieString,
      },
      options?.headers || {}
    );

    // 生成 Secret 头（除非显式禁用）
    if (options?.needSecret !== false) {
      const secret = generateKuwoSecret(cookie[hmKey]);
      if (secret) {
        headers['Secret'] = secret;
      }
    }

    // IP 透传
    if (ip) {
      headers['X-Real-IP'] = ip;
      headers['X-Forwarded-For'] = ip;
    }

    // 序列化请求体
    let data;
    if (Buffer.isBuffer(options?.data)) {
      data = options.data;
    } else if (typeof options?.data === 'object' && options?.data !== null) {
      data = JSON.stringify(options.data);
    } else {
      data = options?.data || undefined;
    }

    // 构建请求配置
    const requestOptions = {
      params,
      data,
      method: options.method || 'GET',
      baseURL: useBaseURL,
      url: options.url,
      headers,
      withCredentials: true,
      responseType: options.responseType || 'json',
      timeout: 15000,
    };

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

      // 响应体
      answer.body = response.data;

      // 响应头
      answer.headers = response.headers;

      // 状态码判断
      if (response.status >= 200 && response.status < 300) {
        answer.status = 200;
        resolve(answer);
      } else {
        answer.status = 502;
        reject(answer);
      }
    } catch (e) {
      answer.status = 502;
      answer.body = { code: e?.response?.status || 0, msg: e?.message || String(e) };
      reject(answer);
    }
  });
};

module.exports = { createRequest };
