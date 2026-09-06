import { fstatSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const markerNames = Object.freeze([
  "FULMAR_INTERNAL_WATCHDOG_DEPTH",
  "FULMAR_ROOT_WATCHDOG_PGID_V1",
  "FULMAR_ROOT_WATCHDOG_PID_V1",
  "FULMAR_ROOT_WATCHDOG_CAPABILITY_V1",
  "FULMAR_ROOT_WATCHDOG_NONCE_V1",
  "FULMAR_ROOT_WATCHDOG_FD_V1"
]);
const project = dirname(dirname(dirname(fileURLToPath(import.meta.url))));

function inheritedDescriptorStdio(descriptor) {
  const stdio = Array(descriptor + 1).fill("ignore");
  stdio[0] = "ignore";
  stdio[1] = "pipe";
  stdio[2] = "pipe";
  stdio[descriptor] = descriptor;
  return stdio;
}

function readAuthenticatedRoot() {
  const present = markerNames.filter((name) => Object.hasOwn(process.env, name));
  if (present.length === 0) return null;
  if (present.length !== markerNames.length) {
    throw new Error("the JavaScript fixture inherited a partial root-watchdog marker set");
  }
  const descriptor = Number(process.env.FULMAR_ROOT_WATCHDOG_FD_V1);
  const rootPID = process.env.FULMAR_ROOT_WATCHDOG_PID_V1;
  const rootPGID = process.env.FULMAR_ROOT_WATCHDOG_PGID_V1;
  const nonce = process.env.FULMAR_ROOT_WATCHDOG_NONCE_V1;
  const capability = process.env.FULMAR_ROOT_WATCHDOG_CAPABILITY_V1;
  const depth = process.env.FULMAR_INTERNAL_WATCHDOG_DEPTH;
  if (descriptor !== 198 || !/^[1-9][0-9]*$/u.test(rootPID)
      || !/^[1-9][0-9]*$/u.test(rootPGID) || !/^[1-8]$/u.test(depth)
      || !/^[a-f0-9]{64}$/u.test(nonce)
      || capability !== `/private/tmp/fulmar-watchdog-capability.${rootPID}.${nonce}`
      || !fstatSync(descriptor).isSocket()) {
    throw new Error("the JavaScript fixture inherited malformed root-watchdog state");
  }
  const capabilityCheck = spawnSync("/usr/bin/perl", [
    join(project, "scripts", "attest-watchdog-capability-fd.pl"),
    String(descriptor), nonce, rootPID, rootPGID
  ], { stdio: inheritedDescriptorStdio(descriptor) });
  if (capabilityCheck.error || capabilityCheck.status !== 0 || capabilityCheck.signal !== null) {
    throw new Error("the JavaScript fixture could not authenticate its root-watchdog descriptor");
  }
  const relationshipCheck = spawnSync(process.execPath, [
    join(project, "scripts", "bounded-process-group-inspector.mjs"),
    "root-attest", rootPID, rootPGID, capability, nonce
  ], { stdio: ["ignore", "ignore", "ignore"] });
  if (relationshipCheck.error || relationshipCheck.status !== 0 || relationshipCheck.signal !== null) {
    throw new Error("the JavaScript fixture could not authenticate its root-watchdog relationship");
  }
  return Object.freeze({
    descriptor,
    environment: Object.freeze(Object.fromEntries(markerNames.map((name) => [name, process.env[name]])))
  });
}

const authenticatedRoot = readAuthenticatedRoot();

export const isInsideAuthenticatedRootWatchdog = authenticatedRoot !== null;

export function rootWatchdogChildOptions(options = {}) {
  if (!authenticatedRoot) return { ...options };
  if (options.stdio !== undefined) {
    throw new Error("rootWatchdogChildOptions owns stdio so descriptor 198 cannot be dropped");
  }
  return {
    ...options,
    env: { ...(options.env ?? process.env), ...authenticatedRoot.environment },
    stdio: inheritedDescriptorStdio(authenticatedRoot.descriptor)
  };
}

export function rootWatchdogLogicalArguments(argumentsList) {
  return authenticatedRoot ? ["--inherit-root", ...argumentsList] : [...argumentsList];
}
