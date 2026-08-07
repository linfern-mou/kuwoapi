/**
 * @fileoverview KuwoMusicApi 程序化 API 入口模块
 *
 * 本模块是项目的编程式调用入口（区别于 index.js 的 HTTP 服务入口），
 * 负责：
 * 1. 扫描 `module/` 目录下所有 API 模块文件并动态加载
 * 2. 为每个模块创建统一的包装函数，自动处理 Cookie 格式转换
 * 3. 将所有 API 函数与服务器工具、请求工具合并后统一导出
 *
 * 导出结构为扁平对象，模块文件名（去 .js 后缀）即为 API 函数名。
 * 例如：`module/search.js` → `api.search(params)`
 *
 * @module main
 * @requires node:fs
 * @requires path
 * @requires ./util - 工具函数（cookieToJson 等）
 * @requires ./server - 服务器管理（startService、getModulesDefinitions）
 * @requires ./util/request - 底层 HTTP 请求工具（createRequest）
 *
 * @example
 * // 作为库使用（编程式调用，不启动 HTTP 服务）
 * const api = require('./main');
 *
 * // 搜索音乐
 * const searchRes = await api.search({
 *   key: '海阔天空'
 * });
 */

const fs = require('node:fs');
const path = require('path');
const { cookieToJson } = require('./util');

/**
 * 动态注册的 API 函数集合
 *
 * 键为模块文件名（去 .js 后缀），值为对应的包装函数。
 * 例如：`{ search: [Function], login: [Function], ... }`
 *
 * @type {Record<string, (data?: Record<string, any>) => Promise<any>>}
 */
let obj = {};

/**
 * 动态扫描并加载 module/ 目录下的所有 API 模块
 */
fs.readdirSync(path.join(__dirname, 'module'))
  .reverse()
  .forEach((file) => {
    if (!file.endsWith('.js')) return;

    let fileModule = require(path.join(__dirname, 'module', file));
    let fn = file.split('.').shift() || '';

    obj[fn] = (data = {}) => {
      if (typeof data.cookie === 'string') data.cookie = cookieToJson(data.cookie);

      return fileModule({ ...data, cookie: data.cookie ? data.cookie : {} }, (...args) => {
        const { createRequest } = require('./util/request');
        return createRequest(...args);
      });
    };
  });

/**
 * 统一导出
 */
module.exports = { ...require('./server'), ...require('./util/request'), ...obj };
