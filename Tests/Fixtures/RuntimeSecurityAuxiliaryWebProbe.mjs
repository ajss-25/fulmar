import assert from "node:assert/strict";
import net from "node:net";

const bridgeSymbol = Symbol.for("com.fulmar.runtime.approved-web-fetch.v1");
const bridge = globalThis[bridgeSymbol];
assert.equal(typeof bridge?.normalize, "function");
assert.equal(typeof bridge?.fetch, "function");

assert.equal(bridge.normalize("https://Example.com/path#fragment"), "https://example.com/path");
for (const blocked of [
  "http://example.com/",
  "https://example.com:444/",
  "https://user:secret@example.com/",
  "https://127.0.0.1/",
  "https://[::1]/",
  "https://localhost/",
  "https://service.local/",
  "https://singlelabel/"
]) {
  assert.throws(() => bridge.normalize(blocked), (error) => error?.code === "EACCES", blocked);
}

assert.throws(
  () => fetch("https://example.com/direct"),
  (error) => error?.code === "EACCES",
  "ordinary fetch must not inherit approved-page egress"
);
const response = await bridge.fetch("https://example.com/approved");
assert.equal(await response.text(), "GUARDED_TLS_OK");
assert.equal(typeof globalThis.__localHarnessLastTLSOptions.lookup, "function");
assert.equal(globalThis.__localHarnessLastSocketOptions.lookup, globalThis.__localHarnessLastTLSOptions.lookup);
await new Promise((resolve) => {
  globalThis.__localHarnessLastTLSOptions.lookup("different.example", {}, (error) => {
    assert.equal(error?.code, "EACCES");
    resolve();
  });
});
assert.throws(
  () => fetch("https://example.com/after"),
  (error) => error?.code === "EACCES",
  "approved-page capability must not escape its operation"
);
assert.throws(
  () => net.Socket.prototype.connect.call({}, {
    host: "example.com",
    port: 443,
    lookup: globalThis.__localHarnessLastTLSOptions.lookup
  }),
  (error) => error?.code === "EACCES",
  "the reviewed lookup hook must not be reusable after the approved operation"
);
await assert.rejects(
  bridge.fetch("https://private.example.com/ssrf"),
  (error) => error?.code === "EACCES" && /private or reserved/u.test(error.message),
  "resolved private addresses must be rejected before content is returned"
);

process.stdout.write("Approved auxiliary HTTPS fetch probe passed.\n");
