'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { createGateway } = require('../src/app');
const { UserStore } = require('../src/users');

const SECRET = 'test-secret-that-is-at-least-32-characters';
let upstream;
let gateway;
let baseUrl;

// Fake legacy service: echoes back what it received.
function startUpstream() {
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString(),
      }));
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

before(async () => {
  upstream = await startUpstream();
  const config = {
    upstream: { hostname: '127.0.0.1', port: upstream.address().port },
    jwt: { secret: SECRET, issuer: 'hw2-gateway', audience: 'legacy-httpbin', ttlSeconds: 60 },
  };
  const users = new UserStore({ alice: bcrypt.hashSync('wonderland', 4) });
  gateway = createGateway(config, users);
  await new Promise((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${gateway.address().port}`;
});

after(() => {
  gateway.close();
  upstream.close();
});

async function login(username, password) {
  return fetch(`${baseUrl}/auth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
}

function sign(claims, options = {}) {
  return jwt.sign(claims, SECRET, {
    algorithm: 'HS256', issuer: 'hw2-gateway', audience: 'legacy-httpbin', expiresIn: 60, ...options,
  });
}

test('login with correct credentials returns a bearer token', async () => {
  const res = await login('alice', 'wonderland');
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.token_type, 'Bearer');
  assert.equal(body.expires_in, 60);
  assert.equal(jwt.decode(body.access_token).sub, 'alice');
});

test('login with wrong password or unknown user is rejected', async () => {
  assert.equal((await login('alice', 'wrong')).status, 401);
  assert.equal((await login('bob', 'wonderland')).status, 401);
});

test('login with malformed body returns 400', async () => {
  const res = await fetch(`${baseUrl}/auth/token`, { method: 'POST', body: 'not json' });
  assert.equal(res.status, 400);
});

test('request without a token never reaches the upstream', async () => {
  const res = await fetch(`${baseUrl}/get`);
  assert.equal(res.status, 401);
  assert.match(res.headers.get('www-authenticate'), /^Bearer/);
});

test('expired, forged and alg=none tokens are rejected', async () => {
  const expired = sign({ sub: 'alice' }, { expiresIn: -10 });
  const forged = jwt.sign({ sub: 'alice' }, 'another-secret-another-secret-123', {
    issuer: 'hw2-gateway', audience: 'legacy-httpbin', expiresIn: 60,
  });
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: 'alice', iss: 'hw2-gateway', aud: 'legacy-httpbin', exp: Math.floor(Date.now() / 1000) + 60,
  })).toString('base64url');
  const none = `${header}.${payload}.`;
  const noExp = jwt.sign({ sub: 'alice' }, SECRET, { issuer: 'hw2-gateway', audience: 'legacy-httpbin' });

  for (const token of [expired, forged, none, noExp]) {
    const res = await fetch(`${baseUrl}/get`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(res.status, 401, `token should be rejected: ${token}`);
  }
});

test('valid token is forwarded with identity headers and without the token', async () => {
  const { access_token: token } = await (await login('alice', 'wonderland')).json();
  const res = await fetch(`${baseUrl}/anything?x=1`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'x-authenticated-user': 'admin', // spoof attempt
      'content-type': 'text/plain',
    },
    body: 'hello',
  });
  assert.equal(res.status, 200);
  const echoed = await res.json();
  assert.equal(echoed.method, 'POST');
  assert.equal(echoed.url, '/anything?x=1');
  assert.equal(echoed.body, 'hello');
  assert.equal(echoed.headers['x-authenticated-user'], 'alice');
  assert.equal(echoed.headers.authorization, undefined);
});

test('upstream being down gives 502', async () => {
  const config = {
    upstream: { hostname: '127.0.0.1', port: 1 },
    jwt: { secret: SECRET, issuer: 'hw2-gateway', audience: 'legacy-httpbin', ttlSeconds: 60 },
  };
  const broken = createGateway(config, new UserStore({}));
  await new Promise((resolve) => broken.listen(0, '127.0.0.1', resolve));
  const res = await fetch(`http://127.0.0.1:${broken.address().port}/get`, {
    headers: { authorization: `Bearer ${sign({ sub: 'alice' })}` },
  });
  assert.equal(res.status, 502);
  broken.close();
});
