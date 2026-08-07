#!/usr/bin/env node
/**
 * test_network_v2.js
 * 测试 kuwo 网络可达性。所有访问必须通过 HTTP_PROXY 环境变量
 * (127.0.0.1:18080) 的 CONNECT 隧道进行。
 *
 * 测试目标：
 *   1. rid.kuwo.cn/sig.s 签名刷新接口 + DNS 解析(net.connect 直连 80)
 *   2. deliver.kuwo.cn/yl_res_manage.search 资源搜索接口
 *   3. deliver.kuwo.cn/yl_res_manage.spread 接口 (config.ini spreadurl)
 *   4. 39.156.123.34 直接 TCP 连接 (act.log resserver)
 */
const net = require('net');
const zlib = require('zlib');
const dns = require('dns');

// ---- 从 HTTP_PROXY 环境变量解析代理地址，默认 127.0.0.1:18080 ----
function parseProxy() {
  const raw = process.env.HTTP_PROXY || process.env.http_proxy || 'http://127.0.0.1:18080';
  const m = raw.match(/^https?:\/\/([^:/]+)(?::(\d+))?/);
  if (m) return { host: m[1], port: m[2] ? parseInt(m[2], 10) : 18080 };
  return { host: '127.0.0.1', port: 18080 };
}
const PROXY_HOST = parseProxy().host;
const PROXY_PORT = parseProxy().port;

// ---- 代理 CONNECT 隧道函数（按任务模板）----
function viaProxy(targetHost, targetPort, reqBuf, timeout = 15000) {
  return new Promise((resolve) => {
    const sock = net.connect(PROXY_PORT, PROXY_HOST, () => {
      sock.write(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n\r\n`);
    });
    let state = 0, cbuf = [], rchunks = [];
    sock.on('data', (d) => {
      if (state === 0) {
        cbuf.push(d);
        const t = Buffer.concat(cbuf).toString('latin1');
        if (t.includes('\r\n\r\n')) {
          if (/^HTTP\/1\.[01] 200/.test(t)) { state = 1; sock.write(reqBuf); }
          else { sock.destroy(); resolve({ err: 'CONNECT failed: ' + t.split('\r\n')[0] }); }
        }
      } else rchunks.push(d);
    });
    sock.on('end', () => state === 1 ? resolve(Buffer.concat(rchunks)) : resolve({ err: 'end-before-tunnel' }));
    sock.on('error', e => resolve({ err: e.message }));
    sock.setTimeout(timeout, () => { sock.destroy(); resolve({ err: 'timeout', got: rchunks.length ? Buffer.concat(rchunks) : null }); });
  });
}

// ---- 工具函数 ----
const UA = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)';

// 判断 buffer 是否主要为可打印文本
function isText(buf) {
  if (!buf || buf.length === 0) return true;
  const n = Math.min(buf.length, 512);
  let printable = 0;
  for (let i = 0; i < n; i++) {
    const c = buf[i];
    if ((c >= 0x20 && c < 0x7f) || c === 0x09 || c === 0x0a || c === 0x0d) printable++;
  }
  return printable / n > 0.8;
}

// hex dump 前 n 字节
function hexDump(buf, n = 200) {
  if (!buf) return '(null)';
  const slice = buf.slice(0, n);
  // 每行 16 字节: offset  hex                                 ascii
  let out = [];
  for (let i = 0; i < slice.length; i += 16) {
    const line = slice.slice(i, i + 16);
    const hex = Array.from(line).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(line).map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
    out.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return out.join('\n');
}

// 尝试 zlib 解压：在 buffer 中查找 0x78 0x9c 头
function tryZlib(buf) {
  if (!buf) return null;
  const idx = buf.indexOf(Buffer.from([0x78, 0x9c]));
  if (idx < 0) return null;
  try {
    const inf = zlib.inflateSync(buf.slice(idx));
    return { offset: idx, decompressed: inf };
  } catch (e) {
    return { offset: idx, error: e.message };
  }
}

// 把 HTTP 响应拆成 header / body
function splitHttp(buf) {
  if (!buf) return { head: '', body: Buffer.alloc(0) };
  const text = buf.toString('latin1');
  const idx = text.indexOf('\r\n\r\n');
  if (idx < 0) return { head: text, body: Buffer.alloc(0) };
  return { head: text.slice(0, idx), body: buf.slice(idx + 4) };
}

// 打印请求
function printRequest(label, reqStr) {
  console.log(`\n----- [REQUEST] ${label} -----`);
  console.log(reqStr.replace(/\r\n/g, '\r\n').replace(/\r\n/g, '\\r\\n\n').replace(/\\r\\n$/, ''));
}

// 简化打印请求（保留可见 \r\n）
function showReq(label, reqStr) {
  console.log(`\n----- [REQUEST] ${label} -----`);
  console.log(reqStr.split('\r\n').join('\r\n'));
}

// 打印响应（综合：二进制 hex / 文本全文 / zlib 解压）
function showResponse(label, resp) {
  console.log(`\n----- [RESPONSE] ${label} -----`);
  if (!resp) { console.log('(null)'); return; }
  if (resp.err) {
    console.log(`错误: ${resp.err}`);
    if (resp.got && resp.got.length) {
      console.log(`  partial (${resp.got.length} bytes):`);
      console.log(hexDump(resp.got, 200));
    }
    return;
  }
  const buf = resp; // Buffer
  const { head, body } = splitHttp(buf);
  console.log(`总长度: ${buf.length} 字节, body 长度: ${body.length} 字节`);
  console.log(`--- 响应头 ---`);
  console.log(head || '(无 HTTP 头，可能是裸 TCP 响应)');

  if (body.length === 0) {
    // 也许整个响应都是裸 TCP（非 HTTP）
    console.log(`--- body 为空，打印整体前 200 字节 hex ---`);
    console.log(hexDump(buf, 200));
    return;
  }

  if (isText(body)) {
    console.log(`--- body (文本, 全文) ---`);
    console.log(body.toString('utf8'));
  } else {
    console.log(`--- body (二进制, 前 200 字节 hex dump) ---`);
    console.log(hexDump(body, 200));
    // 同时尝试 latin1 文本预览
    console.log(`--- body 前 200 字节 latin1 预览 ---`);
    console.log(JSON.stringify(body.slice(0, 200).toString('latin1')));
  }

  // 尝试 zlib 解压（找 0x78 0x9c 头）
  const z = tryZlib(body);
  if (z) {
    if (z.decompressed) {
      console.log(`--- zlib 解压成功 (zlib 头位于 body 偏移 ${z.offset}, 解压后 ${z.decompressed.length} 字节) ---`);
      const dstr = z.decompressed.toString('utf8');
      console.log(dstr);
    } else {
      console.log(`--- zlib 头位于偏移 ${z.offset}, 但解压失败: ${z.error} ---`);
    }
  } else {
    console.log(`--- 未发现 zlib 头 (0x78 0x9c) ---`);
  }
}

// ---- 主流程 ----
(async () => {
  console.log(`代理: ${PROXY_HOST}:${PROXY_PORT}  (HTTP_PROXY=${process.env.HTTP_PROXY || process.env.http_proxy || '(未设置, 使用默认)'})`);

  // act.log 真实 sig1/sig2（刷新后），非 search 接口的 S1/S2
  const SIG1 = 2316766655;
  const SIG2 = 3918679961;
  const RID = 'MUSIC_1108461';

  // body: 用 <MUSIC_1108461> 替换 <rid> 字面量
  const body = `<001><U_QRY>|<${SIG1},${SIG2}>|<0><><>|<>|<${RID}>|<uip:0.0.0.0:0>|<new>|<nat:0>|<flags:0><speer>|<ipdeny:no>|<loginid:>\r\n`;
  const bodyLen = Buffer.byteLength(body);

  // ============================================================
  // [1] rid.kuwo.cn/sig.s 签名刷新接口 + DNS 解析
  // ============================================================
  console.log('\n\n========================================');
  console.log('测试 1: rid.kuwo.cn/sig.s 签名刷新接口');
  console.log('========================================');

  // 1a. DNS 解析（dns.lookup）
  console.log('\n>> 1a. rid.kuwo.cn DNS 解析 (dns.lookup)');
  const dnsResult = await new Promise(resolve => {
    dns.lookup('rid.kuwo.cn', { all: true }, (err, addrs) => resolve({ err, addrs }));
  });
  if (dnsResult.err) {
    console.log(`  DNS 解析失败: ${dnsResult.err.message}`);
  } else {
    console.log(`  DNS 解析成功: ${JSON.stringify(dnsResult.addrs)}`);
  }

  // 1b. net.connect 直接连接 80 端口（不经过代理，测试本地直连可达性）
  console.log('\n>> 1b. rid.kuwo.cn:80 net.connect 直连（不经代理）');
  const directConn = await new Promise(resolve => {
    const s = net.connect(80, 'rid.kuwo.cn', () => {
      resolve({ ok: true, hadError: false });
      s.destroy();
    });
    s.setTimeout(5000, () => { s.destroy(); resolve({ ok: false, hadError: false, err: 'timeout' }); });
    s.on('error', e => resolve({ ok: false, hadError: true, err: e.message }));
  });
  if (directConn.ok) {
    console.log('  直连成功: rid.kuwo.cn:80 可达（DNS 解析 + TCP 连接均成功）');
  } else {
    console.log(`  直连失败: ${directConn.hadError ? directConn.err : '超时'}（本地无法直接访问，需走代理）`);
  }

  // 1c. 通过代理 CONNECT 隧道请求 sig.s
  console.log('\n>> 1c. rid.kuwo.cn/sig.s 经代理 CONNECT 隧道');
  const sigReq = `GET /sig.s?w=${RID}&c=mbox HTTP/1.0\r\nHost: rid.kuwo.cn\r\nUser-Agent: ${UA}\r\nConnection: close\r\n\r\n`;
  showReq('1c. rid.kuwo.cn GET /sig.s', sigReq);
  let sig1Val = null, sig2Val = null;
  const sigResp = await viaProxy('rid.kuwo.cn', 80, Buffer.from(sigReq));
  showResponse('1c. rid.kuwo.cn /sig.s', sigResp);
  if (!sigResp.err) {
    const { body: sigBody } = splitHttp(sigResp);
    const sigText = sigBody.toString('latin1');
    const m1 = sigText.match(/sig1=(\S+)/i);
    const m2 = sigText.match(/sig2=(\S+)/i);
    if (m1) sig1Val = m1[1];
    if (m2) sig2Val = m2[1];
    console.log(`\n>> 提取 sig1/sig2:`);
    console.log(`   sig1 = ${sig1Val || '(未找到)'}`);
    console.log(`   sig2 = ${sig2Val || '(未找到)'}`);
  }

  // ============================================================
  // [2] deliver.kuwo.cn/yl_res_manage.search 资源搜索接口
  // ============================================================
  console.log('\n\n========================================');
  console.log('测试 2: deliver.kuwo.cn/yl_res_manage.search');
  console.log('========================================');
  console.log(`POST body (len=${bodyLen}): ${JSON.stringify(body)}`);
  const searchReq =
    `POST /yl_res_manage.search HTTP/1.1\r\n` +
    `Host: deliver.kuwo.cn\r\n` +
    `User-Agent: ${UA}\r\n` +
    `Cache-Control: no-cache\r\n` +
    `Accept-Encoding: zlib\r\n` +
    `Content-Length: ${bodyLen}\r\n` +
    `Connection: close\r\n` +
    `\r\n` +
    `${body}`;
  showReq('2. deliver.kuwo.cn POST /yl_res_manage.search', searchReq);
  const searchResp = await viaProxy('deliver.kuwo.cn', 80, Buffer.from(searchReq));
  showResponse('2. deliver.kuwo.cn /yl_res_manage.search', searchResp);
  if (!searchResp.err) {
    const { body: sBody } = splitHttp(searchResp);
    const t = sBody.toString('latin1');
    console.log(`\n>> 标签检查:`);
    console.log(`   包含 <URL>: ${/<URL>/.test(t)}`);
    console.log(`   包含 <FILE_LEN>: ${/<FILE_LEN>/.test(t)}`);
    console.log(`   包含 <CHECKSUM>: ${/<CHECKSUM>/.test(t)}`);
  }

  // ============================================================
  // [3] deliver.kuwo.cn/yl_res_manage.spread 接口 (config.ini spreadurl)
  // ============================================================
  console.log('\n\n========================================');
  console.log('测试 3: deliver.kuwo.cn/yl_res_manage.spread (config.ini spreadurl)');
  console.log('========================================');
  const spreadReq =
    `POST /yl_res_manage.spread HTTP/1.1\r\n` +
    `Host: deliver.kuwo.cn\r\n` +
    `User-Agent: ${UA}\r\n` +
    `Cache-Control: no-cache\r\n` +
    `Accept-Encoding: zlib\r\n` +
    `Content-Length: ${bodyLen}\r\n` +
    `Connection: close\r\n` +
    `\r\n` +
    `${body}`;
  showReq('3. deliver.kuwo.cn POST /yl_res_manage.spread', spreadReq);
  const spreadResp = await viaProxy('deliver.kuwo.cn', 80, Buffer.from(spreadReq));
  showResponse('3. deliver.kuwo.cn /yl_res_manage.spread', spreadResp);

  // ============================================================
  // [4] 39.156.123.34 直接 TCP 连接 (act.log resserver)
  // ============================================================
  console.log('\n\n========================================');
  console.log('测试 4: 39.156.123.34:80 直接 TCP 连接 (act.log resserver)');
  console.log('========================================');
  const resserverReq =
    `POST /yl_res_manage.search HTTP/1.1\r\n` +
    `Host: deliver.kuwo.cn\r\n` +
    `User-Agent: ${UA}\r\n` +
    `Cache-Control: no-cache\r\n` +
    `Accept-Encoding: zlib\r\n` +
    `Content-Length: ${bodyLen}\r\n` +
    `Connection: close\r\n` +
    `\r\n` +
    `${body}`;
  showReq('4. 39.156.123.34 POST /yl_res_manage.search (经代理 CONNECT 隧道)', resserverReq);
  const resserverResp = await viaProxy('39.156.123.34', 80, Buffer.from(resserverReq));
  showResponse('4. 39.156.123.34 /yl_res_manage.search', resserverResp);

  // ============================================================
  // 汇总
  // ============================================================
  console.log('\n\n========================================');
  console.log('汇总');
  console.log('========================================');
  console.log(`1. rid.kuwo.cn: 代理可达=${!sigResp.err}, sig1=${sig1Val}, sig2=${sig2Val}`);
  console.log(`   DNS lookup=${dnsResult.err ? '失败:' + dnsResult.err.message : '成功 ' + JSON.stringify(dnsResult.addrs)}`);
  console.log(`   直连80=${directConn.ok ? '成功' : '失败(' + (directConn.err || 'timeout') + ')'}`);
  console.log(`2. deliver.kuwo.cn/search: 可达=${!searchResp.err}` + (!searchResp.err ? `, 含<URL>=${/<URL>/.test(splitHttp(searchResp).body.toString('latin1'))}` : ''));
  console.log(`3. deliver.kuwo.cn/spread: 可达=${!spreadResp.err}`);
  console.log(`4. 39.156.123.34:80: 可达=${!resserverResp.err}`);
})();
