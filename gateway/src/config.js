'use strict';

// All settings come from environment variables so the same image can be
// used anywhere; secrets never live in the source tree.

function required(env, name) {
  const value = env[name];
  if (!value) {
    throw new Error(`missing required environment variable ${name}`);
  }
  return value;
}

function loadConfig(env = process.env) {
  const secret = required(env, 'JWT_SECRET');
  if (secret.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }

  const upstream = new URL(env.UPSTREAM_URL || 'http://127.0.0.1:8081');

  return {
    listenHost: env.LISTEN_HOST || '0.0.0.0',
    listenPort: Number(env.LISTEN_PORT || 8080),
    upstream: {
      hostname: upstream.hostname,
      port: Number(upstream.port || 80),
    },
    jwt: {
      secret,
      issuer: env.JWT_ISSUER || 'hw2-gateway',
      audience: env.JWT_AUDIENCE || 'legacy-httpbin',
      ttlSeconds: Number(env.JWT_TTL_SECONDS || 900),
    },
    usersFile: env.USERS_FILE || 'users.json',
  };
}

module.exports = { loadConfig };
