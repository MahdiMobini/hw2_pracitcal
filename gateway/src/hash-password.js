'use strict';

// Prints a bcrypt hash to put in users.json:
//   npm run hash-password -- 'my password'
const bcrypt = require('bcryptjs');

const password = process.argv[2];
if (!password) {
  console.error('usage: node src/hash-password.js <password>');
  process.exit(1);
}
console.log(bcrypt.hashSync(password, 12));
