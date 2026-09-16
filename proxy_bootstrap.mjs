// Node's global fetch ignores both network.httpProxy and the proxy environment,
// so an agent provider built on it resolves DNS itself and fails inside the
// sandbox, where direct egress is denied. Point the global dispatcher at the
// supervisor's proxy. The proxy still enforces the domain allowlist and TLS, so
// this reaches nothing the policy did not already allow.
const proxy = process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
if (proxy) {
  const undici = new URL('runtime/node_modules/undici/index.js', import.meta.url);
  const { ProxyAgent, setGlobalDispatcher } = await import(undici);
  const address = new URL(proxy);
  // The generated proxy carries credentials in the URL; undici wants them as a
  // header instead, and the address itself must not keep them.
  const credentials = address.username
    ? 'Basic ' + Buffer.from(decodeURIComponent(address.username) + ':' +
                             decodeURIComponent(address.password)).toString('base64')
    : undefined;
  address.username = '';
  address.password = '';
  setGlobalDispatcher(new ProxyAgent(credentials ? {uri: address.toString(), token: credentials}
                                                 : {uri: address.toString()}));
}
