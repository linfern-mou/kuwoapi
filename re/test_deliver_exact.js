#!/usr/bin/env node
/* 精确测试 deliver.kuwo.cn 搜索接口（基于逆向 bodyfmt 0x1005BD28）
 * 通过 HTTP_PROXY(127.0.0.1:18080) CONNECT 隧道访问
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
    let state = 0; // 0=connect, 1=tunnel
    let cbuf = [];
    let rchunks = [];
    sock.on('data', (d) => {
      if (state === 0) {
        cbuf.push(d);
        const t = Buffer.concat(cbuf).toString('latin1');
        if (t.includes('\r\n\r\n')) {
          if (/^HTTP\/1\.[01] 200/.test(t)) {
            state = 1;
            sock.write(reqBuf);
          } else {
            sock.destroy();
            resolve({err: 'CONNECT failed: ' + t.split('\r\n')[0]});
          }
        }
      } else {
        rchunks.push(d);
      }
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
  const head = text.slice(0, hi);
  const body = r.slice(hi+4);
  return {status: head.split('\r\n')[0], head, body};
}

const UA = 'Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)';

// bodyfmt: <%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|<uip:%s>|<new>|<nat:%u>|<flags:%u><speer>|<ipdeny:no>%s|<loginid:%s>\r\n
function buildBody(sig1, sig2) {
  return `<001><U_QRY>|<${sig1},${sig2}>|<0><><>|<>|<rid>|<uip:0.0.0.0:0>|<new>|<nat:0>|<flags:0><speer>|<ipdeny:no>|<loginid:>\r\n`;
}

function showBody(label, body) {
  if (!body) { console.log(`  ${label}: (empty)`); return; }
  console.log(`  ${label}: len=${body.length}`);
  console.log(`    hex: ${body.slice(0,64).toString('hex')}`);
  console.log(`    latin1: ${body.slice(0,200).toString('latin1')}`);
  // 尝试 zlib inflate
  try {
    const inf = zlib.inflateSync(body);
    console.log(`    zlib-inflate: len=${inf.length} ${inf.slice(0,200).toString('latin1')}`);
  } catch(e) {}
  try {
    const inf = zlib.inflateRawSync(body);
    console.log(`    zlib-raw: len=${inf.length} ${inf.slice(0,200).toString('latin1')}`);
  } catch(e) {}
  // 尝试 base64 decode
  try {
    const b = Buffer.from(body.toString('latin1').trim(), 'base64');
    if (b.length > 0 && /^[\x20-\x7e\r\n]+$/.test(b.toString('latin1').slice(0,100))) {
      console.log(`    base64-decode: ${b.slice(0,200).toString('latin1')}`);
    } else if (b.length > 0) {
      console.log(`    base64-decode(hex): ${b.slice(0,64).toString('hex')}`);
      try { const inf = zlib.inflateSync(b); console.log(`    base64+zlib: ${inf.slice(0,200).toString('latin1')}`);}catch(e){}
    }
  } catch(e) {}
}

(async () => {
  // act.log 真实参数
  const sigs = [
    {name:'act.log sig1/sig2 (刷新后)', sig1:2316766655, sig2:3918679961},
    {name:'PLAY_MUSIC S1/S2 (元数据)', sig1:4104424361, sig2:1197033072},
  ];

  for (const s of sigs) {
    const body = buildBody(s.sig1, s.sig2);
    console.log(`\n======== ${s.name} sig1=${s.sig1} sig2=${s.sig2} ========`);
    console.log(`body: ${JSON.stringify(body)}`);

    // POST /yl_res_manage.search
    const req = `POST /yl_res_manage.search HTTP/1.1\r\nHost: deliver.kuwo.cn\r\nUser-Agent: ${UA}\r\nCache-Control: no-cache\r\nAccept-Encoding: zlib\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`;
    console.log(`\n--- POST deliver.kuwo.cn /yl_res_manage.search ---`);
    let r = await httpReq('deliver.kuwo.cn', 80, req);
    if (r.err) { console.log('  ERR:', r.err); if(r.partial) showBody('partial', r.partial); }
    else { console.log('  ', r.status); console.log('  headers:', r.head.split('\r\n').slice(1,6).join(' | ')); showBody('body', r.body); }

    // POST /yl_res_manage.spread
    const req2 = `POST /yl_res_manage.spread HTTP/1.1\r\nHost: deliver.kuwo.cn\r\nUser-Agent: ${UA}\r\nCache-Control: no-cache\r\nAccept-Encoding: zlib\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`;
    console.log(`\n--- POST deliver.kuwo.cn /yl_res_manage.spread ---`);
    r = await httpReq('deliver.kuwo.cn', 80, req2);
    if (r.err) { console.log('  ERR:', r.err); }
    else { console.log('  ', r.status); showBody('body', r.body); }
  }

  // 也测试 search.kuwo.cn/r.s 获取元数据 (确认 S1/S2)
  console.log(`\n======== search.kuwo.cn/r.s 歌曲元数据 ========`);
  const ids = 'MUSIC_1108461';
  const req3 = `GET /r.s?stype=musicinfo&itemset=music_2014&alflac=1&pcmp4=1&ids=${ids} HTTP/1.0\r\nHost: search.kuwo.cn\r\nUser-Agent: ${UA}\r\nConnection: close\r\n\r\n`;
  let r = await httpReq('search.kuwo.cn', 80, req3);
  if (r.err) console.log('  ERR:', r.err);
  else {
    console.log('  ', r.status);
    showBody('body', r.body);
  }
})();
