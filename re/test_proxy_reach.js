#!/usr/bin/env node
/**
 * 测试代理是否真到达 kuwo 服务器 - 用已知可用端点对比
 */
const net = require('node:net');
const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 18080;

function httpViaProxy(method, host, path, body) {
  return new Promise((resolve) => {
    const bodyBuf = body ? Buffer.from(body) : null;
    const headers = {
      'Host': host,
      'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)',
      'Connection': 'close',
    };
    if (bodyBuf) {
      headers['Content-Length'] = bodyBuf.length;
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
    }
    const sock = net.connect(PROXY_PORT, PROXY_HOST, () => {
      let req = `${method} http://${host}${path} HTTP/1.1\r\n`;
      for (const [k,v] of Object.entries(headers)) req += `${k}: ${v}\r\n`;
      req += '\r\n';
      sock.write(req);
      if (bodyBuf) sock.write(bodyBuf);
    });
    let buf = Buffer.alloc(0);
    const t = setTimeout(() => {
      resolve({ status: -2, err: 'timeout', body: buf });
      sock.destroy();
    }, 15000);
    sock.on('data', (d) => { buf = Buffer.concat([buf, d]); });
    sock.on('end', () => {
      clearTimeout(t);
      resolve({ status: 0, body: buf });
    });
    sock.on('error', (e) => {
      clearTimeout(t);
      resolve({ status: -3, err: e.message, body: buf });
    });
  });
}

function httpViaConnect(method, host, port, path, body) {
  return new Promise((resolve) => {
    const bodyBuf = body ? Buffer.from(body) : null;
    const sock = net.connect(PROXY_PORT, PROXY_HOST, () => {
      sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);
    });
    let state = 'connect';
    let buf = Buffer.alloc(0);
    const t = setTimeout(() => {
      resolve({ status: -2, err: 'timeout', body: buf });
      sock.destroy();
    }, 15000);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (state === 'connect') {
        const idx = buf.indexOf('\r\n\r\n');
        if (idx >= 0) {
          const conn = buf.slice(0, idx).toString('latin1');
          if (conn.match(/200/)) {
            state = 'tunnel';
            let req = `${method} ${path} HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: Mozilla/4.0\r\nConnection: close\r\n\r\n`;
            sock.write(req);
            buf = buf.slice(idx + 4);
          } else {
            clearTimeout(t);
            resolve({ status: -1, err: 'CONNECT failed: ' + conn, body: buf });
            sock.destroy();
          }
        }
      }
    });
    sock.on('end', () => {
      if (state === 'tunnel') {
        clearTimeout(t);
        resolve({ status: 0, body: buf });
      }
    });
    sock.on('error', (e) => {
      clearTimeout(t);
      resolve({ status: -3, err: e.message, body: buf });
    });
  });
}

(async () => {
  // 1) 已知可用: search.kuwo.cn (r.s 端点)
  console.log('=== [1] search.kuwo.cn / (验证代理通) ===');
  let r = await httpViaProxy('GET', 'search.kuwo.cn', '/');
  console.log(`  viaProxy: status=${r.status} err=${r.err||''} len=${r.body?.length||0}`);
  if (r.body) console.log('  ' + r.body.toString('latin1').slice(0, 200).replace(/\r?\n/g, '\n  '));

  // 2) rid.kuwo.cn (sig.s 端点)
  console.log('\n=== [2] rid.kuwo.cn /sig.s?w=MUSIC_1108461&c=mbox ===');
  r = await httpViaProxy('GET', 'rid.kuwo.cn', '/sig.s?w=MUSIC_1108461&c=mbox');
  console.log(`  status=${r.status} err=${r.err||''} len=${r.body?.length||0}`);
  if (r.body) console.log('  ' + r.body.toString('latin1').slice(0, 300).replace(/\r?\n/g, '\n  '));

  // 3) deliver.kuwo.cn 各路径
  console.log('\n=== [3] deliver.kuwo.cn / ===');
  r = await httpViaProxy('GET', 'deliver.kuwo.cn', '/');
  console.log(`  status=${r.status} err=${r.err||''} len=${r.body?.length||0}`);
  if (r.body) console.log('  ' + r.body.toString('latin1').slice(0, 300).replace(/\r?\n/g, '\n  '));

  // 4) deliver.kuwo.cn 直接 CONNECT 隧道 (绕过代理缓存)
  console.log('\n=== [4] deliver.kuwo.cn via CONNECT /yl_res_manage.search (POST) ===');
  const body = `<001><U_QRY>|<2316766655,3918679961>|<0><><>|<0.0.0.0>|<rid>|<uip:0.0.0.0:0>|<new>|<nat:0>|<flags:262144><speer>|<ipdeny:no>|<loginid:>\r\n`;
  r = await httpViaConnect('POST', 'deliver.kuwo.cn', 80, '/yl_res_manage.search', body);
  console.log(`  status=${r.status} err=${r.err||''} len=${r.body?.length||0}`);
  if (r.body) console.log('  ' + r.body.toString('latin1').slice(0, 400).replace(/\r?\n/g, '\n  '));

  // 5) 试试 resserver IP 直接连接 (39.156.123.34)
  console.log('\n=== [5] 39.156.123.34:80 via CONNECT /yl_res_manage.search (POST) ===');
  r = await httpViaConnect('POST', '39.156.123.34', 80, '/yl_res_manage.search', body);
  console.log(`  status=${r.status} err=${r.err||''} len=${r.body?.length||0}`);
  if (r.body) console.log('  ' + r.body.toString('latin1').slice(0, 400).replace(/\r?\n/g, '\n  '));

  // 6) 试试用 IP 而不是域名访问 deliver
  console.log('\n=== [6] deliver.kuwo.cn 解析 IP ===');
  require('dns').lookup('deliver.kuwo.cn', {all: true}, (err, addrs) => {
    if (err) console.log('  DNS err: ' + err.message);
    else console.log('  ' + JSON.stringify(addrs));
  });
})();
