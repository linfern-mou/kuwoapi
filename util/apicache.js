/**
 * @fileoverview API 响应缓存中间件
 *
 * 来源: 基于 [Binaryify/NeteaseCloudMusicApi](https://github.com/Binaryify/NeteaseCloudMusicApi) 修改
 *
 * 本模块提供 Express 中间件级别的 API 响应缓存功能，支持：
 * - 内存缓存（默认）和 Redis 缓存（可选）
 * - 按时间字符串（如 "2 minutes"、"1 hour"）设置缓存过期
 * - 按分组管理缓存条目，支持批量清除
 * - 自定义缓存条件（状态码过滤、请求/响应 toggle 函数）
 * - 缓存命中率统计（可选，用于性能监控）
 * - ETag/304 协商缓存支持
 * - JSONP 请求的 URL 去参处理
 *
 * 使用示例：
 *   const cache = require('./apicache').middleware;
 *   app.use(cache('2 minutes', (req, res) => res.statusCode === 200));
 *
 * @module apicache
 * @requires url - URL 解析（用于 JSONP 模式下去除查询参数）
 * @requires ./memory-cache - 内存缓存实现
 */

const url = require('url');
const MemoryCache = require('./memory-cache');

const t = {
  ms: 1,
  second: 1000,
  minute: 60000,
  hour: 3600000,
  day: 3600000 * 24,
  week: 3600000 * 24 * 7,
  month: 3600000 * 24 * 30,
};

const instances = [];

const matches = function (a) {
  return function (b) {
    return a === b;
  };
};

const doesntMatch = function (a) {
  return function (b) {
    return !matches(a)(b);
  };
};

const logDuration = function (d, prefix) {
  const str = d > 1000 ? `${(d / 1000).toFixed(2)}sec` : `${d}ms`;
  return `\x1B[33m- ${prefix ? `${prefix} ` : ''}${str}\x1B[0m`;
};

function getSafeHeaders(res) {
  return res.getHeaders ? res.getHeaders() : res._headers;
}

function ApiCache() {
  const memCache = new MemoryCache();

  const globalOptions = {
    debug: false,
    defaultDuration: 3600000,
    enabled: true,
    appendKey: [],
    jsonp: false,
    redisClient: false,
    headerBlacklist: [],
    statusCodes: {
      include: [],
      exclude: [],
    },
    events: {
      expire: undefined,
    },
    headers: {},
    trackPerformance: false,
  };

  const middlewareOptions = [];
  const instance = this;
  let index = null;
  const timers = {};
  const performanceArray = [];

  instances.push(this);
  this.id = instances.length;

  function debug(a, b, c, d) {
    const arr = ['\x1B[36m[apicache]\x1B[0m', a, b, c, d].filter((arg) => {
      return arg !== undefined;
    });
    const debugEnv = process.env.DEBUG && process.env.DEBUG.split(',').includes('apicache');

    return (globalOptions.debug || debugEnv) && console.log.apply(null, arr);
  }

  function shouldCacheResponse(request, response, toggle) {
    const opt = globalOptions;
    const codes = opt.statusCodes;

    if (!response) {
      return false;
    }

    if (toggle && !toggle(request, response)) {
      return false;
    }

    if (codes.exclude && codes.exclude.length && codes.exclude.includes(response.statusCode)) {
      return false;
    }
    if (codes.include && codes.include.length && codes.include.includes(response.statusCode)) {
      return false;
    }

    return true;
  }

  function addIndexEntries(key, req) {
    const groupName = req.apicacheGroup;

    if (groupName) {
      debug(`group detected "${groupName}"`);
      const group = (index.groups[groupName] = index.groups[groupName] || []);
      group.unshift(key);
    }

    index.all.unshift(key);
  }

  function filterBlacklistedHeaders(headers) {
    return Object.keys(headers)
      .filter((key) => {
        return !globalOptions.headerBlacklist.includes(key);
      })
      .reduce((acc, header) => {
        acc[header] = headers[header];
        return acc;
      }, {});
  }

  function createCacheObject(status, headers, data, encoding) {
    return {
      status,
      headers: filterBlacklistedHeaders(headers),
      data,
      encoding,
      timestamp: new Date().getTime() / 1000,
    };
  }

  function cacheResponse(key, value, duration) {
    const redis = globalOptions.redisClient;
    const expireCallback = globalOptions.events.expire;

    if (redis && redis.connected) {
      try {
        redis.hset(key, 'response', JSON.stringify(value));
        redis.hset(key, 'duration', duration);
        redis.expire(key, duration / 1000, expireCallback || (() => {}));
      } catch (err) {
        debug('[apicache] error in redis.hset()');
      }
    } else {
      memCache.add(key, value, duration, expireCallback);
    }

    timers[key] = setTimeout(() => {
      instance.clear(key, true);
    }, Math.min(duration, 2147483647));
  }

  function accumulateContent(res, content) {
    if (content) {
      if (typeof content == 'string') {
        res._apicache.content = (res._apicache.content || '') + content;
      } else if (Buffer.isBuffer(content)) {
        let oldContent = res._apicache.content;

        if (typeof oldContent === 'string') {
          oldContent = !Buffer.from ? new Buffer(oldContent) : Buffer.from(oldContent);
        }

        if (!oldContent) {
          oldContent = !Buffer.alloc ? Buffer.alloc(0) : Buffer.alloc(0);
        }

        res._apicache.content = Buffer.concat([oldContent, content], oldContent.length + content.length);
      } else {
        res._apicache.content = content;
      }
    }
  }

  function makeResponseCacheable(req, res, next, key, duration, strDuration, toggle) {
    res._apicache = {
      write: res.write,
      writeHead: res.writeHead,
      end: res.end,
      cacheable: true,
      content: undefined,
    };

    Object.keys(globalOptions.headers).forEach((name) => {
      res.setHeader(name, globalOptions.headers[name]);
    });

    res.writeHead = function () {
      if (!globalOptions.headers['cache-control']) {
        if (shouldCacheResponse(req, res, toggle)) {
          res.setHeader('cache-control', `max-age=${(duration / 1000).toFixed(0)}`);
        } else {
          res.setHeader('cache-control', 'no-cache, no-store, must-revalidate');
        }
      }

      res._apicache.headers = Object.assign({}, getSafeHeaders(res));
      return res._apicache.writeHead.apply(this, arguments);
    };

    res.write = function (content) {
      accumulateContent(res, content);
      return res._apicache.write.apply(this, arguments);
    };

    res.end = function (content, encoding) {
      if (shouldCacheResponse(req, res, toggle)) {
        accumulateContent(res, content);

        if (res._apicache.cacheable && res._apicache.content) {
          addIndexEntries(key, req);
          const headers = res._apicache.headers || getSafeHeaders(res);
          const cacheObject = createCacheObject(res.statusCode, headers, res._apicache.content, encoding);
          cacheResponse(key, cacheObject, duration);

          const elapsed = new Date() - req.apicacheTimer;
          debug(`adding cache entry for "${key}" @ ${strDuration}`, logDuration(elapsed));
          debug('_apicache.headers: ', res._apicache.headers);
          debug('res.getHeaders(): ', getSafeHeaders(res));
          debug('cacheObject: ', cacheObject);
        }
      }

      return res._apicache.end.apply(this, arguments);
    };

    next();
  }

  function sendCachedResponse(request, response, cacheObject, toggle, next, duration) {
    if (toggle && !toggle(request, response)) {
      return next();
    }

    const headers = getSafeHeaders(response);

    Object.assign(headers, filterBlacklistedHeaders(cacheObject.headers || {}), {
      'cache-control': `max-age=${Math.max(0, (duration / 1000 - (new Date().getTime() / 1000 - cacheObject.timestamp)).toFixed(0))}`,
    });

    let data = cacheObject.data;
    if (data && data.type === 'Buffer') {
      data = typeof data.data === 'number' ? new Buffer.alloc(data.data) : new Buffer.from(data.data);
    }

    const cachedEtag = cacheObject.headers.etag;
    const requestEtag = request.headers['if-none-match'];

    if (requestEtag && cachedEtag === requestEtag) {
      response.writeHead(304, headers);
      return response.end();
    }

    response.writeHead(cacheObject.status || 200, headers);

    return response.end(data, cacheObject.encoding);
  }

  function syncOptions() {
    for (const i in middlewareOptions) {
      Object.assign(middlewareOptions[i].options, globalOptions, middlewareOptions[i].localOptions);
    }
  }

  this.clear = function (target, isAutomatic) {
    const group = index.groups[target];
    const redis = globalOptions.redisClient;

    if (group) {
      debug(`clearing group "${target}"`);

      group.forEach((key) => {
        debug(`clearing cached entry for "${key}"`);
        clearTimeout(timers[key]);
        delete timers[key];
        if (!globalOptions.redisClient) {
          memCache.delete(key);
        } else {
          try {
            redis.del(key);
          } catch (err) {
            console.log(`[apicache] error in redis.del("${key}")`);
          }
        }
        index.all = index.all.filter(doesntMatch(key));
      });

      delete index.groups[target];
    } else if (target) {
      debug(`clearing ${isAutomatic ? 'expired' : 'cached'} entry for "${target}"`);
      clearTimeout(timers[target]);
      delete timers[target];

      if (!redis) {
        memCache.delete(target);
      } else {
        try {
          redis.del(target);
        } catch (err) {
          console.log(`[apicache] error in redis.del("${target}")`);
        }
      }

      index.all = index.all.filter(doesntMatch(target));

      Object.keys(index.groups).forEach((groupName) => {
        index.groups[groupName] = index.groups[groupName].filter(doesntMatch(target));

        if (!index.groups[groupName].length) {
          delete index.groups[groupName];
        }
      });
    } else {
      debug('clearing entire index');

      if (!redis) {
        memCache.clear();
      } else {
        index.all.forEach((key) => {
          clearTimeout(timers[key]);
          delete timers[key];
          try {
            redis.del(key);
          } catch (err) {
            console.log(`[apicache] error in redis.del("${key}")`);
          }
        });
      }
      this.resetIndex();
    }

    return this.getIndex();
  };

  function parseDuration(duration, defaultDuration) {
    if (typeof duration === 'number') {
      return duration;
    }

    if (typeof duration === 'string') {
      const split = duration.match(/^([\d\.,]+)\s?(\w+)$/);

      if (split.length === 3) {
        const len = Number.parseFloat(split[1]);
        let unit = split[2].replace(/s$/i, '').toLowerCase();
        if (unit === 'm') {
          unit = 'ms';
        }

        return (len || 1) * (t[unit] || 0);
      }
    }

    return defaultDuration;
  }

  this.getDuration = function (duration) {
    return parseDuration(duration, globalOptions.defaultDuration);
  };

  this.getPerformance = function () {
    return performanceArray.map((p) => {
      return p.report();
    });
  };

  this.getIndex = function (group) {
    if (group) {
      return index.groups[group];
    } else {
      return index;
    }
  };

  this.middleware = function cache(strDuration, middlewareToggle, localOptions) {
    const duration = instance.getDuration(strDuration);
    const opt = {};

    middlewareOptions.push({
      options: opt,
    });

    const options = function (localOptions) {
      if (localOptions) {
        middlewareOptions.find((middleware) => {
          return middleware.options === opt;
        }).localOptions = localOptions;
      }

      syncOptions();

      return opt;
    };

    options(localOptions);

    function NOOPCachePerformance() {
      this.report = this.hit = this.miss = function () {};
    }

    function CachePerformance() {
      this.hitsLast100 = new Uint8Array(100 / 4);
      this.hitsLast1000 = new Uint8Array(1000 / 4);
      this.hitsLast10000 = new Uint8Array(10000 / 4);
      this.hitsLast100000 = new Uint8Array(100000 / 4);
      this.callCount = 0;
      this.hitCount = 0;
      this.lastCacheHit = null;
      this.lastCacheMiss = null;

      this.report = function () {
        return {
          lastCacheHit: this.lastCacheHit,
          lastCacheMiss: this.lastCacheMiss,
          callCount: this.callCount,
          hitCount: this.hitCount,
          missCount: this.callCount - this.hitCount,
          hitRate: this.callCount == 0 ? null : this.hitCount / this.callCount,
          hitRateLast100: this.hitRate(this.hitsLast100),
          hitRateLast1000: this.hitRate(this.hitsLast1000),
          hitRateLast10000: this.hitRate(this.hitsLast10000),
          hitRateLast100000: this.hitRate(this.hitsLast100000),
        };
      };

      this.hitRate = function (array) {
        let hits = 0;
        let misses = 0;
        for (let i = 0; i < array.length; i++) {
          let n8 = array[i];
          for (j = 0; j < 4; j++) {
            switch (n8 & 3) {
              case 1:
                hits++;
                break;
              case 2:
                misses++;
                break;
            }
            n8 >>= 2;
          }
        }
        const total = hits + misses;
        if (total == 0) {
          return null;
        }
        return hits / total;
      };

      this.recordHitInArray = function (array, hit) {
        const arrayIndex = ~~(this.callCount / 4) % array.length;
        const bitOffset = (this.callCount % 4) * 2;
        const clearMask = ~(3 << bitOffset);
        const record = (hit ? 1 : 2) << bitOffset;
        array[arrayIndex] = (array[arrayIndex] & clearMask) | record;
      };

      this.recordHit = function (hit) {
        this.recordHitInArray(this.hitsLast100, hit);
        this.recordHitInArray(this.hitsLast1000, hit);
        this.recordHitInArray(this.hitsLast10000, hit);
        this.recordHitInArray(this.hitsLast100000, hit);
        if (hit) {
          this.hitCount++;
        }
        this.callCount++;
      };

      this.hit = function (key) {
        this.recordHit(true);
        this.lastCacheHit = key;
      };

      this.miss = function (key) {
        this.recordHit(false);
        this.lastCacheMiss = key;
      };
    }

    const perf = globalOptions.trackPerformance ? new CachePerformance() : new NOOPCachePerformance();

    performanceArray.push(perf);

    const cache = function (req, res, next) {
      function bypass() {
        debug('bypass detected, skipping cache.');
        return next();
      }

      if (!opt.enabled) {
        return bypass();
      }
      if (req.headers['x-apicache-bypass'] || req.headers['x-apicache-force-fetch']) {
        return bypass();
      }

      req.apicacheTimer = new Date();

      let key = req.hostname + (req.originalUrl || req.url);
      if (opt.jsonp) {
        key = url.parse(key).pathname;
      }

      if (typeof opt.appendKey === 'function') {
        key += `$$appendKey=${opt.appendKey(req, res)}`;
      } else if (opt.appendKey.length > 0) {
        let appendKey = req;

        for (let i = 0; i < opt.appendKey.length; i++) {
          appendKey = appendKey[opt.appendKey[i]];
        }
        key += `$$appendKey=${appendKey}`;
      }

      const redis = opt.redisClient;
      const cached = !redis ? memCache.getValue(key) : null;

      if (cached) {
        const elapsed = new Date() - req.apicacheTimer;
        debug('sending cached (memory-cache) version of', key, logDuration(elapsed));

        perf.hit(key);
        return sendCachedResponse(req, res, cached, middlewareToggle, next, duration);
      }

      if (redis && redis.connected) {
        try {
          redis.hgetall(key, (err, obj) => {
            if (!err && obj && obj.response) {
              const elapsed = new Date() - req.apicacheTimer;
              debug('sending cached (redis) version of', key, logDuration(elapsed));

              perf.hit(key);
              return sendCachedResponse(req, res, JSON.parse(obj.response), middlewareToggle, next, duration);
            } else {
              perf.miss(key);
              return makeResponseCacheable(req, res, next, key, duration, strDuration, middlewareToggle);
            }
          });
        } catch (err) {
          perf.miss(key);
          return makeResponseCacheable(req, res, next, key, duration, strDuration, middlewareToggle);
        }
      } else {
        perf.miss(key);
        return makeResponseCacheable(req, res, next, key, duration, strDuration, middlewareToggle);
      }
    };

    cache.options = options;

    return cache;
  };

  this.options = function (options) {
    if (options) {
      Object.assign(globalOptions, options);
      syncOptions();

      if ('defaultDuration' in options) {
        globalOptions.defaultDuration = parseDuration(globalOptions.defaultDuration, 3600000);
      }

      if (globalOptions.trackPerformance) {
        debug('WARNING: using trackPerformance flag can cause high memory usage!');
      }

      return this;
    } else {
      return globalOptions;
    }
  };

  this.resetIndex = function () {
    index = {
      all: [],
      groups: {},
    };
  };

  this.newInstance = function (config) {
    const instance = new ApiCache();

    if (config) {
      instance.options(config);
    }

    return instance;
  };

  this.clone = function () {
    return this.newInstance(this.options());
  };

  this.resetIndex();
}

module.exports = new ApiCache();
