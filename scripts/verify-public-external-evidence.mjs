import { basename } from "node:path";
import { readAttestedRegularFile } from "./attested-regular-file.mjs";
import {
  PUBLIC_RELEASE_PROFILE_NAMES,
  resolvePublicReleaseProfile,
  verifyPublicExternalEvidenceBytes
} from "./public-release-profile-policy.mjs";

const USAGE = "usage: verify-public-external-evidence.mjs <evidence> <candidate-sha256> <version> <build> [--profile <stable|beta>]";

// The default four-operand invocation is the unchanged stable contract. A beta
// candidate must name its profile explicitly; the profile is never inferred from
// the evidence contents or from the environment.
const operands = process.argv.slice(2);
let profileName;
if (operands.length === 6 && operands[4] === "--profile") {
  profileName = operands[5];
  if (!PUBLIC_RELEASE_PROFILE_NAMES.includes(profileName)) {
    throw new Error(`unknown public release profile: ${String(profileName).slice(0, 64)}`);
  }
  operands.splice(4, 2);
}
if (operands.length !== 4) {
  throw new Error(USAGE);
}
const [path, expectedSHA, expectedVersion, rawBuild] = operands;
const expectedBuild = Number(rawBuild);
if (!path || !/^[a-f0-9]{64}$/u.test(expectedSHA ?? "")
    || !/^\d+\.\d+\.\d+$/u.test(expectedVersion ?? "")
    || !/^\d+$/u.test(rawBuild ?? "")
    || !Number.isSafeInteger(expectedBuild) || expectedBuild < 1) {
  throw new Error(USAGE);
}
const profile = resolvePublicReleaseProfile(profileName);
let evidenceFile;
try {
  evidenceFile = await readAttestedRegularFile(path, {
    label: "public external evidence",
    minimumBytes: 2,
    maximumBytes: 1024 * 1024,
    requireCurrentUser: true,
    requirePrivateMode: true,
    requireSingleLink: true
  });
} catch (error) {
  if (error?.code === "ENOENT") {
    throw new Error("public external evidence is missing for the exact candidate");
  }
  throw error;
}
const result = verifyPublicExternalEvidenceBytes(evidenceFile.bytes, {
  profile: profile.name,
  expectedSHA256: expectedSHA,
  expectedVersion,
  expectedBuild
});
process.stdout.write(`${basename(evidenceFile.path)} is ${result.summary}\n`);
