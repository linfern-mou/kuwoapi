#!/usr/bin/env node
/**
 * 实证验证 deliver.kuwo.cn 资源检索接口
 * 请求格式来源：KwMV.dll 反汇编（非猜测）
 *   - URL: POST /yl_res_manage.search HTTP/1.1, Host: deliver.kuwo.cn
 *   - Body fmt: <%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|<uip:%s>|<new>|<nat:%u>|<flags:%u><speer>|<ipdeny:no>%s|<loginid:%s>
 *   - UA: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)
 *   - Accept-Encoding: zlib
 */
const http = require('node:http');
const zlib = require('node:zlib');
const net = require('node:net');

const RID = process.argv[2] || 'MUSIC_1108461'; // Letting Go - 蔡健雅 (来自 act.log)
const KID = 15277654; // 来自 act.log

// Step 1: 从 search.kuwo.cn/r.s?stype=musicinfo 获取 sig1/sig2 (已确认接口)
function getMeta(rid) {
  return new Promise((resolve, reject) => {
    const ids = rid.startsWith('MUSIC_') ? rid : `MUSIC_${rid}`;
    const path = `/r.s?stype=musicinfo&itemset=music_2014&alflac=1&pcmp4=1&ids=${ids}`;
    const req = http.request({
      host: 'search.kuwo.cn', path, method: 'GET',
      headers: { 'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)' },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        if (buf.length < 10) return reject(new Error(`meta too short: ${buf.length}`));
        try {
          const text = zlib.inflateSync(buf.slice(8)).toString('utf-8');
          resolve(text);
        } catch (e) { reject(new Error(`inflate fail: ${e.message}, head=${buf.slice(0,20).toString('hex')}`)); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// Step 2: POST deliver.kuwo.cn/yl_res_manage.search (反汇编确认的格式)
function searchDeliver(rid, sig1, sig2, kid, uip) {
  return new Promise((resolve, reject) => {
    const body = `<001><U_QRY>|<${sig1},${sig2}>|<${kid}><0><0>|<0>|<rid>|<uip:${uip}>|<new>|<nat:0>|<flags:0><speer>|<ipdeny:no>0|<loginid:0>\r\n`;
    const bodyBuf = Buffer.from(body, 'utf-8');
    const header =
      `POST /yl_res_manage.search HTTP/1.1\r\n` +
      `Host: deliver.kuwo.cn\r\n` +
      `User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)\r\n` +
      `Cache-Control: no-cache\r\n` +
      `Accept-Encoding: zlib\r\n` +
      `Content-Length: ${bodyBuf.length}\r\n` +
      `Connection: Keep-Alive\r\n` +
      `\r\n`;
    console.log('=== deliver 请求 ===');
    console.log(header + body);

    const sock = net.connect(80, 'deliver.kuwo.cn', () => {
      sock.write(header);
      sock.write(bodyBuf);
    });
    const chunks = [];
    sock.on('data', (c) => chunks.push(c));
    sock.on('end', () => {
      const buf = Buffer.concat(chunks);
      resolve(buf);
    });
    sock.on('error', reject);
    setTimeout(() => { sock.destroy(); resolve(Buffer.concat(chunks)); }, 8000);
  });
}

(async () => {
  console.log(`=== Step 1: 获取 ${RID} 元数据 (sig1/sig2) ===`);
  let meta;
  try { meta = await getMeta(RID); }
  catch (e) { console.error('meta fail:', e.message); return; }
  console.log(meta.substring(0, 800));

  // 解析 S1/S2
  const qualities = [];
  for (const line of meta.split(/\r?\n/)) {
    const idx = line.indexOf('=');
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim();
    const val = line.slice(idx + 1).trim();
    if (/^\d+$/.test(key)) {
      const parts = val.split('|');
      const q = { code: key };
      for (const p of parts) {
        const ci = p.indexOf(':');
        if (ci < 0) continue;
        const k = p.slice(0, ci).trim();
        const v = p.slice(ci + 1).trim();
        if (k === 'S1') q.sig1 = v;
        else if (k === 'S2') q.sig2 = v;
        else if (k === 'SIZE') q.filesize = v;
        else if (k === 'BT') q.bitrate = v;
      }
      qualities.push(q);
    }
  }
  console.log('\n=== 解析到的音质 ===');
  console.log(JSON.stringify(qualities, null, 2));
  if (!qualities.length) { console.error('无音质数据'); return; }

  const q = qualities[qualities.length - 1]; // 取最高音质
  console.log(`\n使用: sig1=${q.sig1} sig2=${q.sig2} size=${q.filesize}`);

  console.log(`\n=== Step 2: POST deliver.kuwo.cn/yl_res_manage.search ===`);
  const uip = '192.168.1.7'; // 来自 act.log DEVICE_INFO
  const resp = await searchDeliver(RID, q.sig1, q.sig2, KID, uip);
  console.log('\n=== deliver 原始响应 (前 2000 字节) ===');
  console.log(resp.slice(0, 2000).toString('latin1'));
  console.log('\n=== 响应总长度 ===', resp.length);
})().catch(e => console.error(e));
