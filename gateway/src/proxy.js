'use strict';

const http = require('node:http');

// Hop-by-hop headers describe a single connection, not the request, so a
// proxy must not pass them on (RFC 9110, section 7.6.1).
const HOP_BY_HOP = [
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
];

// Headers the client must not be able to set: the token itself stays at the
// gateway and identity headers are always written by the gateway.
const CLIENT_CONTROLLED = [
  'authorization',
  'x-authenticated-user',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
];

function stripHeaders(headers, names) {
  const result = { ...headers };
  // Headers named in "Connection" are hop-by-hop as well.
  const listed = (headers.connection || '').split(',').map((h) => h.trim().toLowerCase());
  for (const name of [...names, ...listed]) {
    delete result[name];
  }
  return result;
}

// Streams the client request to the upstream and the answer back.
function forward(req, res, upstream, username) {
  const headers = stripHeaders(req.headers, [...HOP_BY_HOP, ...CLIENT_CONTROLLED]);
  headers['x-authenticated-user'] = username;
  headers['x-forwarded-for'] = req.socket.remoteAddress;
  headers['x-forwarded-host'] = req.headers.host || '';
  headers['x-forwarded-proto'] = 'http';

  const upstreamReq = http.request({
    hostname: upstream.hostname,
    port: upstream.port,
    method: req.method,
    path: req.url,
    headers,
    timeout: 30_000,
  });

  upstreamReq.on('response', (upstreamRes) => {
    res.writeHead(upstreamRes.statusCode, stripHeaders(upstreamRes.headers, HOP_BY_HOP));
    upstreamRes.pipe(res);
  });

  upstreamReq.on('timeout', () => upstreamReq.destroy(new Error('upstream timed out')));

  upstreamReq.on('error', (err) => {
    console.error(`upstream error: ${err.message}`);
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'bad_gateway' }));
    } else {
      res.destroy();
    }
  });

  req.pipe(upstreamReq);
}

module.exports = { forward };
