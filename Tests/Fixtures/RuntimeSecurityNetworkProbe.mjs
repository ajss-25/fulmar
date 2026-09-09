import assert from "node:assert/strict";
import dns from "node:dns";
import dgram from "node:dgram";
import http from "node:http";
import http2 from "node:http2";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";

const host = "93.184.216.34";
const approvedPort = 443;
const wrongPort = 444;
const approvedHTTPHost = "192.168.1.20";
const approvedHTTPPort = 8080;
const loopbackHost = "127.0.0.1";
const approvedLoopbackPort = 11434;
const wrongLoopbackPort = 11435;

function denied(operation, label) {
  assert.throws(
    operation,
    (error) => error?.code === "EACCES",
    `${label} must fail synchronously at the preloader boundary`
  );
}

function admitted(operation, label) {
  let handle;
  assert.doesNotThrow(() => { handle = operation(); }, label);
  handle?.on?.("error", () => {});
  handle?.destroy?.();
  handle?.close?.();
}

denied(() => net.connect(wrongPort, host), "net.connect wrong port");
denied(() => net.connect(approvedPort, host), "raw net.connect to HTTPS origin");
denied(() => net.connect(approvedHTTPPort, approvedHTTPHost), "raw net.connect to non-loopback HTTP origin");
denied(() => net.connect(wrongLoopbackPort, loopbackHost), "connected loopback wrong port");
admitted(() => net.connect(approvedLoopbackPort, loopbackHost), "connected loopback exact origin");
denied(() => net.createConnection(wrongPort, host), "net.createConnection wrong port");
denied(() => net.createConnection(approvedPort, host), "raw net.createConnection to HTTPS origin");
denied(
  () => net.connect({ host, port: approvedPort, lookup: (_name, _options, callback) => callback(null, loopbackHost, 4) }),
  "net.connect custom resolver"
);
denied(() => net.connect("/var/run/local-harness-bypass.sock"), "Unix socket path");
denied(
  () => net.connect({ path: "/var/run/local-harness-bypass.sock" }),
  "Unix socket options"
);

const deniedSocket = new net.Socket();
denied(() => deniedSocket.connect(wrongPort, host), "Socket.connect wrong port");
deniedSocket.destroy();
const admittedSocket = new net.Socket();
denied(() => admittedSocket.connect(approvedPort, host), "raw Socket.connect to HTTPS origin");
admittedSocket.destroy();
const forgedTLS = new tls.TLSSocket(new net.Socket());
denied(() => forgedTLS.connect(approvedPort, host), "unvalidated TLSSocket.connect");
forgedTLS.destroy();

denied(() => tls.connect(wrongPort, host), "tls.connect wrong port");
denied(
  () => tls.connect({ host, port: approvedPort, lookup: (_name, _options, callback) => callback(null, loopbackHost, 4) }),
  "tls.connect custom resolver"
);
denied(
  // This hostile fixture must attempt disabled verification to prove the
  // runtime guard rejects it before a transport is opened.
  () => tls.connect({ host, port: approvedPort, rejectUnauthorized: false }), // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
  "tls.connect disabled certificate verification"
);
denied(
  () => tls.connect({ host, port: approvedPort, servername: "unapproved.example" }),
  "tls.connect mismatched SNI"
);
denied(
  () => tls.connect(approvedPort, host, { port: wrongPort }),
  "tls.connect options override"
);
denied(() => tls.connect(approvedPort, host), "direct tls.connect exact origin");
denied(
  () => tls.connect({
    host,
    port: approvedPort,
    get localAddress() {
      net.connect(approvedPort, host);
      return undefined;
    }
  }),
  "TLS option getter raw-TCP reentrancy"
);
let nestedGetterReached = false;
const hostileALPN = [];
Object.defineProperty(hostileALPN, 0, {
  get() {
    nestedGetterReached = true;
    const forged = new net.Socket();
    Object.setPrototypeOf(forged, tls.TLSSocket.prototype);
    forged.connect(approvedPort, host);
    return "h2";
  }
});
hostileALPN.length = 1;
denied(
  () => tls.connect({ host, port: approvedPort, ALPNProtocols: hostileALPN }),
  "nested TLS option getter cannot create a raw transport scope"
);
assert.equal(nestedGetterReached, false, "direct TLS must be denied before nested option evaluation");

denied(
  () => https.request(`https://${host}:${approvedPort}/`, { port: wrongPort }),
  "HTTPS URL options override"
);
denied(
  () => http.request({ protocol: "http:", hostname: host, port: approvedPort }),
  "HTTP scheme mismatch"
);
denied(
  () => https.request({ protocol: "https:", hostname: host, port: approvedPort }),
  "direct HTTPS exact origin"
);
denied(
  () => http.request({ protocol: "http:", hostname: approvedHTTPHost, port: approvedHTTPPort }),
  "direct non-loopback HTTP exact origin"
);
admitted(
  () => http.request({ protocol: "http:", hostname: loopbackHost, port: approvedLoopbackPort }),
  "direct literal-loopback HTTP exact origin"
);
denied(
  () => https.request(`https://${host}:${approvedPort}/`, {
    lookup: (_name, _options, callback) => callback(null, loopbackHost, 4)
  }),
  "HTTPS custom resolver"
);
denied(
  () => https.request(`https://${host}:${approvedPort}/`, { agent: new https.Agent() }),
  "HTTPS custom agent"
);
denied(
  // This is a denied negative-security probe, never a production request.
  () => https.request(`https://${host}:${approvedPort}/`, { rejectUnauthorized: false }), // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
  "HTTPS disabled certificate verification"
);
denied(
  () => https.request(`https://${host}:${approvedPort}/`, { headers: { Host: "unapproved.example" } }),
  "HTTPS Host override"
);
denied(
  () => https.get(`https://${host}:${approvedPort}/`, { port: wrongPort }),
  "HTTPS get URL options override"
);
denied(
  () => https.globalAgent.createConnection({ host, port: wrongPort }),
  "HTTPS Agent wrong port"
);
denied(
  () => https.globalAgent.createConnection({
    host,
    port: approvedPort,
    lookup: (_name, _options, callback) => callback(null, loopbackHost, 4)
  }),
  "HTTPS Agent custom resolver"
);
denied(
  () => https.globalAgent.createConnection({ host, port: approvedPort }),
  "direct HTTPS Agent exact origin"
);

denied(() => http2.connect(`https://${host}:${wrongPort}`), "HTTP/2 wrong port");
denied(
  () => http2.connect(`https://${host}:${approvedPort}`, { port: wrongPort }),
  "HTTP/2 options override"
);
denied(
  () => http2.connect(`https://${host}:${approvedPort}`, { createConnection: () => new net.Socket() }),
  "HTTP/2 custom connection factory"
);
denied(
  () => http2.connect(`https://${host}:${approvedPort}`, {
    lookup: (_name, _options, callback) => callback(null, loopbackHost, 4)
  }),
  "HTTP/2 custom resolver"
);
denied(
  () => http2.connect(`https://${host}:${approvedPort}`),
  "direct HTTP/2 exact origin"
);

denied(() => fetch(`https://${host}:${wrongPort}/`), "fetch wrong port");
const aborted = new AbortController();
aborted.abort();
await fetch(`https://${host}:${approvedPort}/`, { signal: aborted.signal }).catch(() => {});
const abortedHTTP = new AbortController();
abortedHTTP.abort();
// This aborted request exercises the explicitly approved HTTP-origin guard;
// it cannot complete and is isolated to the runtime-security fixture.
await fetch(`http://${approvedHTTPHost}:${approvedHTTPPort}/`, { signal: abortedHTTP.signal }).catch(() => {}); // nosemgrep: typescript.react.security.react-insecure-request.react-insecure-request
denied(
  () => fetch(`https://${host}:${approvedPort}/`, { dispatcher: { dispatch() {} } }),
  "fetch custom dispatcher"
);
denied(
  () => fetch(`https://${host}:${approvedPort}/`, { headers: { Host: "unapproved.example" } }),
  "fetch init Host override"
);
const requestWithHostOverride = new Request(`https://${host}:${approvedPort}/`, {
  headers: new Headers({ Host: "unapproved.example" })
});
denied(
  () => fetch(requestWithHostOverride),
  "fetch Request Host override"
);
denied(
  () => fetch(`https://${host}:${approvedPort}/`, { connect: {} }),
  "fetch unreviewed transport option"
);
denied(
  () => fetch(`https://${host}:${approvedPort}/`, {
    method: "POST",
    body: new ReadableStream({ pull() {} }),
    duplex: "half"
  }),
  "fetch caller-controlled streaming body"
);
denied(() => new WebSocket(`wss://${host}:${wrongPort}/`), "WebSocket wrong port");
denied(
  () => new WebSocket(`wss://${host}:${approvedPort}/`, ["openai-codex-responses"]),
  "unreviewed WebSocket at exact approved provider origin"
);

// DNS resolution is a non-forgeable capability of the guarded transport. It
// is never exposed as a direct plugin/tool API, even for an approved hostname.
denied(() => dns.lookup("unapproved.example", () => {}), "DNS unapproved host");
denied(() => dns.lookup(host, () => {}), "DNS exact approved host");
denied(() => dns.setServers(["8.8.8.8"]), "custom DNS resolver");

denied(() => net.createServer().listen(0), "unspecified TCP listener");
denied(() => net.createServer().listen(0, "0.0.0.0"), "all-interface TCP listener");
denied(
  () => net.createServer().listen("/private/tmp/local-harness-bypass.sock"),
  "Unix-domain listener"
);
const loopbackServer = net.createServer();
loopbackServer.on("error", () => {});
assert.doesNotThrow(
  () => loopbackServer.listen(0, "127.0.0.1", () => loopbackServer.close()),
  "explicit loopback TCP listener"
);

const deniedDatagram = dgram.createSocket("udp4");
denied(() => deniedDatagram.bind(0, "0.0.0.0"), "all-interface datagram listener");
const loopbackDatagram = dgram.createSocket("udp4");
loopbackDatagram.on("error", () => {});
assert.doesNotThrow(
  () => loopbackDatagram.bind(0, "127.0.0.1", () => loopbackDatagram.close()),
  "explicit loopback datagram listener"
);

const connectedDatagram = dgram.createSocket("udp4");
denied(
  () => connectedDatagram.connect(approvedLoopbackPort, loopbackHost),
  "connected-mode loopback datagram connect"
);
connectedDatagram.close();
const sendingDatagram = dgram.createSocket("udp4");
denied(
  () => sendingDatagram.send(Buffer.from("probe"), approvedLoopbackPort, loopbackHost),
  "connected-mode loopback datagram send"
);
sendingDatagram.close();

process.stdout.write("Runtime network exact-origin probe passed.\n");
