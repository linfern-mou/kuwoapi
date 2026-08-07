#!/usr/bin/env node
/**
 * 测试 config.ini 中 SearchServer1/2/3 (DWORD编码IP) 是否响应搜索请求
 * SearchServer1=1008520484 -> 60.9.52.164
 * SearchServer2=3546558734 -> 211.99.9.14
 * SearchServer3=1008591533 -> 60.10.78.77
 * resserver (from act.log) = 39.156.123.34
 */
const net = require('node:net');
const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 18080;

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
    }, 12000);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (state === 'connect') {
        const idx = buf.indexOf('\r\n\r\n');
        if (idx >= 0) {
          const conn = buf.slice(0, idx).toString('latin1');
          if (conn.match(/200/)) {
            state = 'tunnel';
            let req = `${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)\r\nCache-Control: no-cache\r\nAccept-Encoding: zlib\r\nConnection: close\r\n`;
            if (bodyBuf) {
              req += `Content-Length: ${bodyBuf.length}\r\n\r\n`;
              sock.write(req);
              sock.write(bodyBuf);
            } else {
              req += '\r\n';
              sock.write(req);
            }
            buf = buf.slice(idx + 4);
          } else {
            clearTimeout(t);
            resolve({ status: -1, err: 'CONNECT failed: ' + conn.split('\r\n')[0], body: buf });
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

const sig1 = 2316766655, sig2 = 3918679961;
const body = `<001><U_QRY>|<${sig1},${sig2}>|<0><><>|<0.0.0.0>|<rid>|<uip:0.0.0.0:0>|<new>|<nat:0>|<flags:262144><speer>|<ipdeny:no>|<loginid:>\r\n`;

const servers = [
  { name: 'deliver.kuwo.cn', host: 'deliver.kuwo.cn', port: 80 },
  { name: 'SearchServer1=1008520484', host: '60.9.52.164', port: 80 },
  { name: 'SearchServer2=3546558734', host: '211.99.9.14', port: 80 },
  { name: 'SearchServer3=1008591533', host: '60.10.78.77', port: 80 },
  { name: 'resserver-from-actlog', host: '39.156.123.34', port: 80 },
];

(async () => {
  for (const svr of servers) {
    console.log(`\n=== POST ${svr.host}:${svr.port}/yl_res_manage.search ===`);
    const r = await httpViaConnect('POST', svr.host, svr.port, '/yl_res_manage.search', body);
    console.log(`  status=${r.status} err=${r.err||''} len=${r.body?.length||0}`);
    if (r.body && r.body.length) {
      console.log('  --- response (first 600 bytes) ---');
      console.log(r.body.toString('latin1').slice(0, 600).replace(/\r?\n/g, '\n  '));
    }
  }
})();
