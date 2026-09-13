// Explicit non-Apple release checks. This never changes Keychain trust, signs,
// installs, launches the application, or treats a checksum as legal clearance.
import { createHash } from "node:crypto";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readAttestedRegularFile } from "./attested-regular-file.mjs";
import { runBoundedCommand } from "./prepare-dsh-upgrade.mjs";

const PROJECT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SHA256 = /^[a-f0-9]{64}$/u;
function requireDigest(value) {
  if (!SHA256.test(value ?? "") || value === "0".repeat(64)) throw new Error("an independently reviewed SHA-256 is required");
}

export function verifyPrivateSignerDetails(details, certificateBytes, expectedSignerSHA256) {
  requireDigest(expectedSignerSHA256);
  if (typeof details !== "string" || !/^CodeDirectory .*flags=.*\bruntime\b/mu.test(details)
      || /^Signature=adhoc$/mu.test(details) || !/^Authority=.+$/mu.test(details)
      || /^Authority=Developer ID Application:/mu.test(details)) {
    throw new Error("non-notarized beta requires certificate signing with hardened runtime, not ad-hoc or Developer ID signing");
  }
  if (!Buffer.isBuffer(certificateBytes) || certificateBytes.length < 1
      || certificateBytes.length > 65536
      || createHash("sha256").update(certificateBytes).digest("hex") !== expectedSignerSHA256) {
    throw new Error("candidate signer certificate does not match the independently reviewed SHA-256");
  }
}

export async function verifyPrivateSigner(target, expectedSignerSHA256) {
  requireDigest(expectedSignerSHA256);
  if (!isAbsolute(target) || /[\x00-\x1f\x7f]/u.test(target)) throw new Error("signature target must be one absolute path");
  const scratch = await mkdtemp(join(tmpdir(), "fulmar-nonnotarized-signature."));
  await chmod(scratch, 0o700);
  const environment = { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", HOME: scratch, TMPDIR: `${scratch}/`, LANG: "en_US.UTF-8", LC_CTYPE: "UTF-8" };
  const run = (command, args, extra = {}) => runBoundedCommand(command, args, {
    environment: { ...environment, ...extra }, timeoutMS: 30_000,
    maximumStandardOutputBytes: 1024 * 1024, maximumStandardErrorBytes: 1024 * 1024,
    label: "non-notarized beta signature verification"
  });
  try {
    const prefix = join(scratch, "certificate-");
    const observed = await run("/usr/bin/codesign", ["-dvvv", "--extract-certificates", prefix, target]);
    const certificate = await readAttestedRegularFile(`${prefix}0`, {
      minimumBytes: 1, maximumBytes: 65536, requireCurrentUser: true, requireSingleLink: true
    });
    verifyPrivateSignerDetails(observed.stderr, certificate.bytes, expectedSignerSHA256);
    // This pre-existing verifier permits only CSSMERR_TP_NOT_TRUSTED after
    // structural/resource/CMS verification; all other failures still reject.
    await run("/bin/zsh", ["-f", join(PROJECT, "scripts/verify-code-signature.sh"), target, "--deep", "--strict"], {
      LOCAL_HARNESS_ALLOW_PRIVATE_ROOT: "1"
    });
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

export function verifyNonnotarizedDMGBinding(value, zipSHA256, dmgSHA256, expected = {}) {
  requireDigest(zipSHA256); requireDigest(dmgSHA256);
  const keys = ["schemaVersion", "type", "releaseProfile", "publicBetaQualified", "version", "build", "candidate", "image", "verified", "notProven", "reproducibleDMGBytes"];
  if (!value || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(keys.sort())
      || value.schemaVersion !== 1 || value.type !== "fulmar-nonnotarized-beta-dmg-wrapper"
      || value.releaseProfile !== "nonnotarized-beta" || value.publicBetaQualified !== false
      || value.reproducibleDMGBytes !== false
      || !/^\d+\.\d+\.\d+$/u.test(value.version ?? "") || !Number.isSafeInteger(value.build) || value.build < 1
      || JSON.stringify(Object.keys(value.candidate ?? {}).sort()) !== JSON.stringify(["file", "sha256"])
      || value.candidate.file !== "Fulmar.app.zip" || value.candidate.sha256 !== zipSHA256
      || JSON.stringify(Object.keys(value.image ?? {}).sort()) !== JSON.stringify(["bytes", "file", "sha256"])
      || value.image.file !== "Fulmar.dmg" || value.image.sha256 !== dmgSHA256
      || !Number.isSafeInteger(value.image.bytes) || value.image.bytes < 1
      || (expected.version !== undefined && value.version !== expected.version)
      || (expected.build !== undefined && value.build !== expected.build)
      || (expected.imageBytes !== undefined && value.image.bytes !== expected.imageBytes)
      || JSON.stringify(value.verified) !== JSON.stringify(["candidate-zip-digest", "app-identity", "code-signature-integrity", "read-only-image-roundtrip", "app-tree-bytes-types-modes-links"])
      || JSON.stringify(value.notProven) !== JSON.stringify(["Developer ID distribution trust", "notarisation", "licensing clearance", "physical installation", "providers", "permission persistence"])) {
    throw new Error("DMG binding is not the exact unqualified non-notarized wrapper for the expected candidate and image");
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [command, ...args] = process.argv.slice(2);
    if (command === "verify-signature" && args.length === 2) {
      await verifyPrivateSigner(...args);
    } else if (command === "verify-dmg-binding" && args.length === 6
        && /^\d+\.\d+\.\d+$/u.test(args[3]) && /^[1-9][0-9]*$/u.test(args[4]) && /^[1-9][0-9]*$/u.test(args[5])
        && Number.isSafeInteger(Number(args[4])) && Number.isSafeInteger(Number(args[5]))) {
      const binding = await readAttestedRegularFile(args[0], { minimumBytes: 2, maximumBytes: 65536, requireSingleLink: true });
      verifyNonnotarizedDMGBinding(JSON.parse(binding.bytes), args[1], args[2], {
        version: args[3], build: Number(args[4]), imageBytes: Number(args[5])
      });
    } else {
      throw new Error("usage: nonnotarized-beta-policy.mjs verify-signature <target> <signer-sha256> | verify-dmg-binding <binding.json> <zip-sha256> <dmg-sha256> <version> <build> <image-bytes>");
    }
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
