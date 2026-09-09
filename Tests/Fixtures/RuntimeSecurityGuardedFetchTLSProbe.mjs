import assert from "node:assert/strict";
import tls from "node:tls";

const origin = `https://${process.argv[2] ?? "public.example"}`;
const denied = (operation, label) => assert.throws(
  operation,
  (error) => error?.code === "EACCES",
  label
);

denied(
  () => tls.connect({ host: new URL(origin).hostname, port: 443, servername: new URL(origin).hostname }),
  "direct TLS must be denied before guarded fetch"
);

const response = await fetch(`${origin}/chat/completions`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: "{}"
});
assert.equal(response.status, 200);
assert.equal(await response.text(), "GUARDED_TLS_OK");
assert.equal(globalThis.__localHarnessTLSStubCalls, 1);

denied(
  () => tls.connect({ host: new URL(origin).hostname, port: 443, servername: new URL(origin).hostname }),
  "guarded fetch TLS capability must not escape to its caller"
);
denied(
  () => fetch(`${origin}/chat/completions`, {
    method: "POST",
    body: new ReadableStream({ pull() {} }),
    duplex: "half"
  }),
  "caller-controlled streaming fetch bodies must be denied"
);

process.stdout.write("Guarded HTTPS fetch TLS probe passed.\n");
