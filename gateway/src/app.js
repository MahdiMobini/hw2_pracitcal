'use strict';

const http = require('node:http');
const { issueToken, verifyToken, bearerToken } = require('./tokens');
const { forward } = require('./proxy');

const MAX_LOGIN_BODY = 4 * 1024;

function sendJson(res, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(payload);
}

function readJsonBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(Object.assign(new Error('body too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(Object.assign(new Error('body must be valid JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

// POST /auth/token  {"username": "...", "password": "..."}
async function handleLogin(req, res, config, users) {
  if (req.method !== 'POST') {
    sendJson(res, 405, { error: 'method_not_allowed' }, { allow: 'POST' });
    return;
  }

  let body;
  try {
    body = await readJsonBody(req, MAX_LOGIN_BODY);
  } catch (err) {
    sendJson(res, err.status || 400, { error: 'invalid_request', message: err.message });
    return;
  }

  const { username, password } = body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    sendJson(res, 400, { error: 'invalid_request', message: 'username and password are required' });
    return;
  }

  if (!(await users.verify(username, password))) {
    console.warn(`failed login for "${username}" from ${req.socket.remoteAddress}`);
    sendJson(res, 401, { error: 'invalid_grant', message: 'wrong username or password' });
    return;
  }

  // Same response shape as an OAuth 2.0 token endpoint (RFC 6749, 5.1).
  sendJson(res, 200, {
    access_token: issueToken(username, config.jwt),
    token_type: 'Bearer',
    expires_in: config.jwt.ttlSeconds,
  });
}

function rejectUnauthorized(res, description) {
  sendJson(res, 401, { error: 'invalid_token', message: description }, {
    'www-authenticate': `Bearer realm="hw2-gateway", error="invalid_token", error_description="${description}"`,
  });
}

function handleProxy(req, res, config) {
  const token = bearerToken(req.headers.authorization);
  if (!token) {
    rejectUnauthorized(res, 'missing bearer token');
    return;
  }

  let claims;
  try {
    claims = verifyToken(token, config.jwt);
  } catch (err) {
    rejectUnauthorized(res, err.name === 'TokenExpiredError' ? 'token expired' : 'token is not valid');
    return;
  }

  forward(req, res, config.upstream, claims.sub);
}

function createGateway(config, users) {
  return http.createServer((req, res) => {
    const path = new URL(req.url, 'http://gateway').pathname;

    if (path === '/auth/token') {
      handleLogin(req, res, config, users).catch((err) => {
        console.error(err);
        if (!res.headersSent) sendJson(res, 500, { error: 'internal_error' });
      });
    } else if (path === '/healthz') {
      sendJson(res, 200, { status: 'ok' });
    } else {
      handleProxy(req, res, config);
    }
  });
}

module.exports = { createGateway };
