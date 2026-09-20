// Compatibility shim for bailian-cli console login, never an authorization check.
// Seatbelt permits only the supervisor-allocated callback port. Removing this shim
// cannot grant a different port or access to another local service.
'use strict';
const net = require('node:net');

if (process.env.AGENTBELT_USAGE_LOGIN_ENTRY &&
    process.argv[1] === process.env.AGENTBELT_USAGE_LOGIN_ENTRY) {
  const port = Number(process.env.AGENTBELT_LOOPBACK_PORT);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error('The usage login callback port is missing or invalid.');
  }
  const listen = net.Server.prototype.listen;
  net.Server.prototype.listen = function listenOnGrantedPort(options, ...rest) {
    if (options && typeof options === 'object' && options.port === 0 && options.host === '127.0.0.1') {
      options = {...options, port};
    }
    return listen.call(this, options, ...rest);
  };
}
