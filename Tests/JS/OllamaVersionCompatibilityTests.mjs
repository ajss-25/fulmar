import assert from "node:assert/strict";
import test from "node:test";
import {
  compareOllamaVersions,
  maximumOllamaVersionResponseBytes,
  minimumOllamaVersion,
  parseOllamaVersionResponse,
  parseStableOllamaVersion,
  qualifiedOllamaSeries,
  requireCompatibleOllamaVersion,
  testedOllamaVersion
} from "../../scripts/ollama-version-policy.mjs";

function response(version) {
  return Buffer.from(`{"version":"${version}"}\n`, "utf8");
}

test("Ollama minimum, tested, and later patch releases in the qualified series are admitted", () => {
  assert.equal(minimumOllamaVersion, "0.33.2");
  assert.equal(testedOllamaVersion, "0.33.2");
  assert.equal(qualifiedOllamaSeries, "0.33.x");
  assert.equal(parseOllamaVersionResponse(response(minimumOllamaVersion)).rawValue, "0.33.2");
  assert.equal(parseOllamaVersionResponse(response(testedOllamaVersion)).rawValue, "0.33.2");
  const newer = parseOllamaVersionResponse(
    Buffer.from(' \t{ "version" : "0.33.99+official.arm64" }\r\n', "utf8")
  );
  assert.deepEqual(newer, {
    rawValue: "0.33.99+official.arm64",
    major: 0,
    minor: 33,
    patch: 99,
    buildMetadata: "official.arm64"
  });
  assert.equal(compareOllamaVersions(newer, parseStableOllamaVersion(testedOllamaVersion)), 1);
  for (const unqualified of ["0.34.0", "1.4.0+official.arm64"]) {
    assert.throws(
      () => requireCompatibleOllamaVersion(unqualified),
      /newer than Fulmar's release-qualified 0[.]33[.]x range; install a Fulmar update/u
    );
  }
});

test("an older stable Ollama version fails with the exact actionable floor", () => {
  for (const oldVersion of ["0.32.12", "0.33.1"]) {
    assert.throws(
      () => requireCompatibleOllamaVersion(oldVersion),
      new RegExp(`Ollama ${oldVersion.replaceAll(".", "[.]")} is too old; update to 0\\.33\\.2 or later`, "u")
    );
  }
});

test("hostile Ollama version payloads fail closed", () => {
  const hostile = [
    Buffer.alloc(0),
    Buffer.from("{}"),
    Buffer.from('{"version":null}'),
    Buffer.from('{"version":true}'),
    Buffer.from('{"version":"0.33.2","extra":true}'),
    Buffer.from('{"version":"0.33.2","version":"9.0.0"}'),
    Buffer.from('{"version":"0\\u002e33.2"}'),
    response("00.33.2"),
    response("0.033.2"),
    response("0.33.02"),
    response("0.33"),
    response("0.33.2.1"),
    response("0.33.2-rc.1"),
    response("v0.33.2"),
    response("2147483648.0.0"),
    Buffer.from([0x7b, 0x22, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22,
      0x3a, 0x22, 0xff, 0x22, 0x7d]),
    Buffer.alloc(maximumOllamaVersionResponseBytes + 1, 0x20)
  ];
  for (const payload of hostile) {
    assert.throws(() => parseOllamaVersionResponse(payload));
  }
  assert.throws(() => parseOllamaVersionResponse(new Uint8Array(response("0.33.2"))));
});
