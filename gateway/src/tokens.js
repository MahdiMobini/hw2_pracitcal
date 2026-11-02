'use strict';

const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

// Only HS256 is accepted. Pinning the algorithm blocks tokens signed with
// "none" or with a different algorithm than the one we issue.
const ALGORITHM = 'HS256';

function issueToken(username, jwtConfig) {
  return jwt.sign({}, jwtConfig.secret, {
    algorithm: ALGORITHM,
    subject: username,
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience,
    expiresIn: jwtConfig.ttlSeconds,
    jwtid: crypto.randomUUID(),
  });
}

// Returns the token claims or throws a jsonwebtoken error.
function verifyToken(token, jwtConfig) {
  const claims = jwt.verify(token, jwtConfig.secret, {
    algorithms: [ALGORITHM],
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience,
  });
  // jsonwebtoken accepts tokens without `exp`; we never issue those.
  if (typeof claims.exp !== 'number' || typeof claims.sub !== 'string') {
    throw new jwt.JsonWebTokenError('token must contain exp and sub');
  }
  return claims;
}

// Pulls the token out of "Authorization: Bearer <token>" (RFC 6750).
function bearerToken(header) {
  const match = /^Bearer\s+([A-Za-z0-9\-_.]+)$/i.exec(header || '');
  return match ? match[1] : null;
}

module.exports = { issueToken, verifyToken, bearerToken };
