/**
 * @fileoverview 酷我音乐 API HTTP 请求封装
 *
 * 本模块是所有 API 请求的底层发送函数，负责：
 * 1. 构建请求参数（注入默认设备标识、时间戳等）
 * 2. 根据加密类型生成请求签名（signature/sign）
 * 3. 配置请求头（User-Agent、设备信息、IP 等）
 * 4. 发送 HTTP 请求（通过 axios）
 * 5. 处理响应（解析 Cookie、错误处理）
 *
 * @module request
 */

const axios = require('axios');
const { signKey, signatureAndroidParams, signatureWebParams } = require('./helper');
const { parseCookieString } = require('./util');
const { appid, clientver } = require('./config.json');
const { resolveProxy } = require('./runtime');

/**
 * 创建并发送 API 请求
 */
const createRequest = (options) => {
  return new Promise(async (resolve, reject) => {
    // 从 Cookie 中提取设备标识
    const dev = options?.cookie?.KUWO_API_DEV || '-';
    const guid = options?.cookie?.KUWO_API_GUID || '-';
    const token = options?.cookie?.token || '';
    const userid = options?.cookie?.userid || 0;
    const clienttime = Math.floor(Date.now() / 1000);
    const ip = options?.realIP || options?.ip || '';

    // 构建请求头
    const headers = {
      dev,
      clienttime,
      'kg-rc': '1',
    };

    // IP 透传
    if (ip) {
      headers['X-Real-IP'] = ip;
      headers['X-Forwarded-For'] = ip;
    }

    // 构建默认请求参数
    const defaultParams = {
      dev,
      guid,
      appid,
      clientver,
      clienttime,
    };

    if (token) defaultParams['token'] = token;
    if (userid && userid !== 0) defaultParams['userid'] = userid;

    // 合并默认参数和自定义参数
    const params = options?.clearDefaultParams
      ? options?.params || {}
      : Object.assign({}, defaultParams, options?.params || {});

    headers['clienttime'] = params.clienttime;

    // 生成 signKey（可选）
    if (options?.encryptKey) {
      params['key'] = signKey(params['hash'], params['dev'], params['userid'], params['appid']);
    }

    // 序列化请求体
    const data = Buffer.isBuffer(options?.data)
      ? options.data
      : typeof options?.data === 'object'
      ? JSON.stringify(options.data)
      : options?.data || '';

    // 生成请求签名
    if (!params['signature'] && !options.notSignature) {
      switch (options?.encryptType) {
        case 'web':
          params['signature'] = signatureWebParams(params);
          break;
        case 'android':
        default:
          params['signature'] = signatureAndroidParams(params, data);
          break;
      }
    }

    // 配置请求选项
    options['params'] = params;
    options['baseURL'] = options?.baseURL || 'https://kuwoapi.kuwo.cn';
    options['headers'] = Object.assign(
      { 'User-Agent': 'Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi' },
      options?.headers || {},
      { dev, clienttime: params.clienttime }
    );

    const requestOptions = {
      params,
      data: options?.data,
      method: options.method,
      baseURL: options?.baseURL,
      url: options.url,
      headers: Object.assign({}, options?.headers || {}, headers),
      withCredentials: true,
      responseType: options.responseType,
    };

    // 代理配置
    const proxyConfig = resolveProxy();
    if (proxyConfig) {
      requestOptions.proxy = proxyConfig;
    }

    if (options.data) requestOptions.data = options.data;
    if (params) requestOptions.params = params;

    // 发送请求
    const answer = { status: 500, body: {}, cookie: [], headers: {} };
    try {
      const response = await axios(requestOptions);
      const body = response.data;

      // 解析响应中的 Set-Cookie
      answer.cookie = (response.headers['set-cookie'] || []).map((x) => parseCookieString(x));

      // 解析响应体为 JSON
      try {
        answer.body = JSON.parse(body.toString());
      } catch (error) {
        answer.body = body;
      }

      // 响应状态判断
      if (response.data.status === 0 || (response.data?.error_code && response.data.error_code !== 0)) {
        answer.status = 502;
        reject(answer);
      } else {
        answer.status = 200;
        resolve(answer);
      }
    } catch (e) {
      answer.status = 502;
      answer.body = { status: 0, msg: e };
      reject(answer);
    }
  });
};

module.exports = { createRequest };
