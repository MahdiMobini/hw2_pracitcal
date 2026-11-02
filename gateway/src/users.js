'use strict';

const fs = require('node:fs');
const bcrypt = require('bcryptjs');

// A hash of a random string. It is compared against when the username does
// not exist, so a wrong username and a wrong password take the same time.
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);

class UserStore {
  // `users` maps username -> bcrypt hash.
  constructor(users) {
    this.users = new Map(Object.entries(users));
  }

  static fromFile(path) {
    const parsed = JSON.parse(fs.readFileSync(path, 'utf8'));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error(`${path} must contain a JSON object of username -> bcrypt hash`);
    }
    return new UserStore(parsed);
  }

  async verify(username, password) {
    const hash = this.users.get(username);
    const ok = await bcrypt.compare(password, hash || DUMMY_HASH);
    return ok && hash !== undefined;
  }
}

module.exports = { UserStore };
