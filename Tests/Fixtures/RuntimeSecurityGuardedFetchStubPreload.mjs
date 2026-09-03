import tls from "node:tls";
import net from "node:net";
import dns from "node:dns";
import { EventEmitter } from "node:events";

globalThis.__localHarnessTLSStubCalls = 0;
globalThis.__localHarnessDNSStubCalls = 0;
const fixtureAnswers = Object.freeze({
  "public.example": [{ address: "93.184.216.34", family: 4 }],
  "mixed.example": [
    { address: "93.184.216.34", family: 4 },
    { address: "127.0.0.1", family: 4 }
  ],
  "private.example": [{ address: "127.0.0.1", family: 4 }],
  "private.example.com": [{ address: "127.0.0.1", family: 4 }],
  "rebind.example": [{ address: "93.184.216.34", family: 4 }],
  "public-v6.example": [{ address: "2606:4700:4700::1111", family: 6 }],
  "private-v6.example": [{ address: "fd00::1", family: 6 }],
  "example.com": [{ address: "93.184.216.34", family: 4 }]
});
dns.lookup = function runtimeSecurityDNSLookupStub(hostname, options, callback) {
  globalThis.__localHarnessDNSStubCalls += 1;
  const resolvedOptions = typeof options === "object" && options !== null ? options : {};
  const resolvedCallback = typeof options === "function" ? options : callback;
  const normalizedHost = String(hostname).toLowerCase();
  const literalFamily = net.isIP(normalizedHost);
  const answers = literalFamily === 0
    ? (fixtureAnswers[normalizedHost] ?? [{ address: "93.184.216.34", family: 4 }])
    : [{ address: normalizedHost, family: literalFamily }];
  queueMicrotask(() => {
    if (resolvedOptions.all === true) resolvedCallback(null, answers.map((entry) => ({ ...entry })));
    else resolvedCallback(null, answers[0].address, answers[0].family);
  });
};
net.Socket.prototype.connect = function runtimeSecuritySocketConnectStub(options = {}) {
  globalThis.__localHarnessLastSocketOptions = options;
  return this;
};
tls.connect = function runtimeSecurityTLSStub(options = {}) {
  globalThis.__localHarnessTLSStubCalls += 1;
  globalThis.__localHarnessLastTLSOptions = options;
  const socket = new EventEmitter();
  const requestedHost = String(options.host ?? options.hostname);
  socket.remoteAddress = requestedHost === "rebind.example" || requestedHost.startsWith("private.")
    ? "127.0.0.1"
    : net.isIP(requestedHost) !== 0
      ? requestedHost
      : requestedHost === "public-v6.example" ? "2606:4700:4700::1111" : "93.184.216.34";
  socket.destroyed = false;
  socket.destroy = function destroy(error) {
    socket.destroyed = true;
    if (error) socket.emit("error", error);
  };
  net.Socket.prototype.connect.call(socket, options);
  const finish = () => queueMicrotask(() => socket.emit("secureConnect"));
  if (typeof options.lookup === "function") {
    options.lookup(requestedHost, { all: false }, (error) => {
      if (error) { socket.destroy(error); return; }
      finish();
    });
  } else {
    finish();
  }
  return socket;
};

globalThis.fetch = function runtimeSecurityFetchStub(resource) {
  const url = new URL(resource instanceof Request ? resource.url : resource);
  const host = url.hostname.replace(/^\[|\]$/gu, "");
  return Promise.resolve().then(() => new Promise((resolve, reject) => {
    const socket = tls.connect({
      host,
      port: Number(url.port || 443),
      servername: host
    });
    socket.once("error", reject);
    socket.once("secureConnect", () => {
      if (socket.destroyed) return;
      resolve(new Response("GUARDED_TLS_OK", {
        status: 200,
        headers: { "content-type": "text/plain" }
      }));
    });
  }));
};
