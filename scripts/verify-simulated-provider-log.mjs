import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

function fail(reason, details = {}) {
  throw new Error(`Provider log audit failed: ${reason} ${JSON.stringify(details)}`);
}

export function assertSimulatedProviderLog(rows, model) {
  const chats = rows.filter((row) => row.kind === "chat");
  if (!rows.some((row) => row.kind === "catalog")) fail("catalog-missing");
  if (chats.length < 6) fail("chat-count", { actual: chats.length, minimum: 6 });
  const invalid = chats.filter((row) => row.authorized !== true || row.model !== model || row.stream !== true);
  if (invalid.length !== 0) fail("chat-envelope", { invalid: invalid.length, total: chats.length });

  const freshB = chats.find((row) => row.text.includes("CONTRACT_FRESH_B"));
  if (!freshB) fail("fresh-b-missing");
  if (freshB.text.includes("PRIVATE_OLD_CONTEXT")) fail("fresh-b-context-leak");

  const toolRows = chats.filter((row) => row.text.includes("CONTRACT_TOOL"));
  const advertisesBash = (row) => row.tools.some((name) => String(name).toLowerCase() === "bash");
  const toolRequests = toolRows.filter((row) => advertisesBash(row) && row.toolMessages === undefined);
  if (toolRequests.length !== 1) fail("tool-request-topology", { actual: toolRequests.length });
  const toolResults = toolRows.filter((row) => Array.isArray(row.toolMessages)
    && row.toolMessages.some((message) => message.toolCallId === "call_contract_1"));
  if (toolResults.length !== 1) fail("tool-result-topology", { actual: toolResults.length });
}

function runCLI() {
  const [path, model] = process.argv.slice(2);
  if (!path || !model) throw new Error("Provider log audit arguments are incomplete");
  const raw = readFileSync(path, "utf8").trim();
  const rows = raw === "" ? [] : raw.split("\n").map(JSON.parse);
  assertSimulatedProviderLog(rows, model);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    runCLI();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "Provider log audit failed"}\n`);
    process.exitCode = 1;
  }
}
