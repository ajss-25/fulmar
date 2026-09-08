#!/usr/bin/env node

// Native-only initialization before the DSH process receives its read-only
// composition boundary. The native host admits the private home and verifies
// these bundled bytes before invoking the pinned runtime with one home operand.
import fs from "node:fs";
import { dirname, isAbsolute, join, normalize } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

function prepare() {
  const home = process.argv[2];
  if (process.argv.length !== 3 || process.execArgv.length !== 0
      || typeof home !== "string" || !isAbsolute(home) || normalize(home) !== home
      || home.length > 4096 || /[\u0000-\u001f\u007f]/u.test(home)) {
    throw new Error("invalid preparation arguments");
  }
  const homeMetadata = fs.lstatSync(home);
  if (!homeMetadata.isDirectory() || homeMetadata.isSymbolicLink()
      || homeMetadata.uid !== process.getuid() || (homeMetadata.mode & 0o077) !== 0
      || fs.realpathSync.native(home) !== home) {
    throw new Error("unsafe preparation home");
  }
  const resources = fs.realpathSync.native(dirname(fileURLToPath(import.meta.url)));
  const runtime = join(resources, "Runtime", "dsh");
  const entry = join(runtime, "node_modules", "@deepseek-ai", "dsh-app-boot", "lib", "index.js");
  const anchor = join(runtime, "package.json");
  for (const path of [entry, anchor]) {
    const metadata = fs.lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
        || (metadata.mode & 0o022) !== 0 || fs.realpathSync.native(path) !== path) {
      throw new Error("unsafe bundled preparation input");
    }
  }
  const manifest = JSON.parse(fs.readFileSync(anchor, "utf8"));
  if (manifest.name !== "@deepseek-ai/dsh" || manifest.version !== "0.1.1-rc.1") {
    throw new Error("unreviewed preparation runtime");
  }
  // Imported boot helpers parse only bundled/profile composition here. They do
  // not start plugins, resolve credentials, contact providers or load a model.
  // No ambient HOME, loader, telemetry, credential or DSH setting reaches them.
  for (const key of Object.keys(process.env)) delete process.env[key];
  Object.assign(process.env, {
    HOME: home,
    DSH_HOME: home,
    DSH_AGENTS_HOME: join(home, "Agents"),
    DSH_TELEMETRY_MODE: "DISABLED",
    PATH: "/usr/bin:/bin"
  });
  process.umask(0o077);
  return import(pathToFileURL(entry).href).then(({ healProfilesModuleFallback, loadProfile }) => {
    healProfilesModuleFallback(anchor, home);
    const profile = loadProfile("dsh", "web", anchor, home);
    if (profile.dir !== join(home, "profiles", "web")
        || profile.layers.map(({ packageName }) => packageName).join("\n")
          !== "@deepseek-ai/dsh-base\n@deepseek-ai/dsh-web-app") {
      throw new Error("unreviewed prepared profile");
    }
    process.stdout.write("FULMAR_PROFILE_PREPARED\n");
  });
}

try {
  await prepare();
} catch {
  process.stderr.write("Fulmar could not prepare the private Harness profile safely.\n");
  process.exitCode = 1;
}
