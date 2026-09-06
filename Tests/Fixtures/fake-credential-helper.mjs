#!/usr/bin/env node
import { readFile, rename, writeFile } from "node:fs/promises";

const statePath = process.env.LOCAL_HARNESS_MIGRATION_TEST_STATE;
const controlPath = process.env.LOCAL_HARNESS_MIGRATION_TEST_CONTROL;
if (!statePath || !controlPath) process.exit(90);

const [command, subject] = process.argv.slice(2);
if (!command || !subject) process.exit(91);

async function readJSON(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function writeJSON(path, value) {
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, JSON.stringify(value), { mode: 0o600 });
  await rename(temporary, path);
}

const control = await readJSON(controlPath);
control.calls = (control.calls ?? 0) + 1;
const call = control.calls;
await writeJSON(controlPath, control);

if (control.replaceLeaseAt === call && typeof control.leasePath === "string") {
  const replacement = `${control.leasePath}.${process.pid}.replacement`;
  await writeFile(replacement, "", { mode: 0o600, flag: "wx" });
  await rename(replacement, control.leasePath);
}

if (control.failAt === call) process.exit(2);

const state = await readJSON(statePath);
state.refs ??= {};
state.records ??= {};
const isRecord = command.includes("record");
const collection = isRecord ? state.records : state.refs;

if (command === "get" || command === "get-record") {
  if (!(subject in collection)) process.exit(3);
  let value = String(collection[subject]);
  if (control.corruptAt === call) value += "-corrupt";
  process.stdout.write(value);
  if (control.mutateSourceAt === call && typeof control.sourcePath === "string") {
    await writeFile(control.sourcePath, "version: 1\nrefs:\n  MUTATED: changed\n", { mode: 0o600 });
  }
  process.exit(0);
}

if (command === "set" || command === "set-record") {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  collection[subject] = Buffer.concat(chunks).toString("utf8");
  await writeJSON(statePath, state);
  process.exit(0);
}

if (command === "unset" || command === "unset-record") {
  delete collection[subject];
  await writeJSON(statePath, state);
  process.exit(0);
}

process.exit(92);
