#!/usr/bin/env node
/* 1. 解压 search.kuwo.cn/r.s 元数据
 * 2. 通过代理测试 SearchServer IP / resserver
 */
const net = require('net');
const zlib = require('zlib');

const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 18080;

function viaProxy(targetHost, targetPort, reqBuf, timeout=20000) {
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
          else { sock.destroy(); resolve({err: 'CONNECT failed: ' + t.split('\r\n')[0]}); }
        }
      } else rchunks.push(d);
    });
    sock.on('end', () => state===1 ? resolve(Buffer.concat(rchunks)) : resolve({err:'end-before-tunnel'}));
    sock.on('error', e => resolve({err: e.message}));
    sock.setTimeout(timeout, () => { sock.destroy(); resolve({err:'timeout', got: rchunks.length?Buffer.concat(rchunks):null}); });
  });
}

async function httpReq(host, port, reqStr) {
  const r = await viaProxy(host, port, Buffer.from(reqStr));
  if (r.err) return {err: r.err, partial: r.got};
  const text = r.toString('latin1');
  const hi = text.indexOf('\r\n\r\n');
  if (hi < 0) return {err:'no-header', raw: text.slice(0,200)};
  return {status: text.slice(0,hi).split('\r\n')[0], head: text.slice(0,hi), body: r.slice(hi+4)};
}

const UA = 'Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)';

function buildBody(sig1, sig2) {
  return `<001><U_QRY>|<${sig1},${sig2}>|<0><><>|<>|<rid>|<uip:0.0.0.0:0>|<new>|<nat:0>|<flags:0><speer>|<ipdeny:no>|<loginid:>\r\n`;
}

(async () => {
  // [1] search.kuwo.cn/r.s 元数据
  console.log('======== [1] search.kuwo.cn/r.s musicinfo ========');
  const req1 = `GET /r.s?stype=musicinfo&itemset=music_2014&alflac=1&pcmp4=1&ids=MUSIC_1108461 HTTP/1.0\r\nHost: search.kuwo.cn\r\nUser-Agent: ${UA}\r\nConnection: close\r\n\r\n`;
  let r = await httpReq('search.kuwo.cn', 80, req1);
  if (r.err) console.log('  ERR:', r.err);
  else {
    console.log('  ', r.status);
    console.log('  body hex head:', r.body.slice(0,16).toString('hex'));
    // 8字节头 + zlib
    const zstart = r.body.indexOf(Buffer.from([0x78,0x9c]));
    console.log('  zlib offset:', zstart);
    if (zstart >= 0) {
      try {
        const inf = zlib.inflateSync(r.body.slice(zstart));
        console.log('  zlib inflated ('+inf.length+'):');
        console.log(inf.toString('utf8'));
      } catch(e) { console.log('  inflate err:', e.message); }
    }
  }

  // [2] SearchServer IP 通过代理 POST
  const sig1=2316766655, sig2=3918679961;
  const body = buildBody(sig1, sig2);
  const targets = [
    {host:'60.9.52.164', name:'SearchServer1'},
    {host:'211.99.9.14', name:'SearchServer2'},
    {host:'60.10.78.77', name:'SearchServer3'},
    {host:'39.156.123.34', name:'act.log resserver'},
  ];
  for (const t of targets) {
    console.log(`\n======== [2] POST ${t.host} (${t.name}) /yl_res_manage.search ========`);
    const req = `POST /yl_res_manage.search HTTP/1.1\r\nHost: ${t.host}\r\nUser-Agent: ${UA}\r\nCache-Control: no-cache\r\nAccept-Encoding: zlib\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`;
    r = await httpReq(t.host, 80, req);
    if (r.err) { console.log('  ERR:', r.err); if(r.partial) console.log('  partial hex:', r.partial.slice(0,64).toString('hex')); }
    else {
      console.log('  ', r.status);
      console.log('  body hex:', r.body.slice(0,64).toString('hex'));
      console.log('  body latin1:', r.body.slice(0,200).toString('latin1'));
    }

    // 也测试 GET ?<body>
    console.log(`--- GET ${t.host} /yl_res_manage.search?<body> ---`);
    const reqg = `GET /yl_res_manage.search?${encodeURIComponent(body)} HTTP/1.0\r\nHost: ${t.host}\r\nUser-Agent: ${UA}\r\nConnection: close\r\n\r\n`;
    r = await httpReq(t.host, 80, reqg);
    if (r.err) console.log('  ERR:', r.err);
    else {
      console.log('  ', r.status);
      console.log('  body hex:', r.body.slice(0,64).toString('hex'));
      console.log('  body latin1:', r.body.slice(0,200).toString('latin1'));
    }
  }
})();
