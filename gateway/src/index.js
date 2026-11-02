'use strict';

const { loadConfig } = require('./config');
const { UserStore } = require('./users');
const { createGateway } = require('./app');

const config = loadConfig();
const users = UserStore.fromFile(config.usersFile);
const server = createGateway(config, users);

server.listen(config.listenPort, config.listenHost, () => {
  const { hostname, port } = config.upstream;
  console.log(`gateway listening on ${config.listenHost}:${config.listenPort}, upstream ${hostname}:${port}`);
});

// Docker sends SIGTERM on "docker compose down": stop accepting new
// connections and let in-flight requests finish.
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    console.log(`${signal} received, shutting down`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  });
}
