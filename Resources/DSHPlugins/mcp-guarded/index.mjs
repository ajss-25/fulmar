import { fileURLToPath } from "node:url";
import { apply as applyBundledMCP } from "@deepseek-ai/dsh-mcp-client";
import { credentialRef } from "@deepseek-ai/dsh-credentials";
import z from "@deepseek-ai/schemastery";
import { loadApprovedCatalog } from "./catalog-core.mjs";
import {
  buildGuardChildEnvironment,
  createGuardedContext,
  resolveCredentialEnvironment
} from "./guarded-runtime.mjs";

delete process.env.LOCAL_HARNESS_MCP_PLUGIN;

const name = "mcp-guarded";
const inject = ["tools", "credentials", "approval"];
const Config = z.object({
  catalogPath: z.string().required()
});
const runnerPath = fileURLToPath(new URL("./stdio-guard-runner.mjs", import.meta.url));

async function apply(ctx, config) {
  const catalog = loadApprovedCatalog(config.catalogPath);
  const sandboxTemp = process.env.LOCAL_HARNESS_SANDBOX_TEMP;
  if (typeof sandboxTemp !== "string" || sandboxTemp.length === 0) {
    throw new Error("mcp-guarded: the native sandbox temp root is unavailable");
  }
  for (const plan of catalog.plans) {
    const credentials = await resolveCredentialEnvironment(ctx, plan, credentialRef);
    const environment = buildGuardChildEnvironment({ plan, credentials, sandboxTemp });
    const guardedContext = createGuardedContext(ctx, plan);
    await applyBundledMCP(guardedContext, {
      transport: "stdio",
      serverName: plan.dsh.serverName,
      command: process.execPath,
      args: [runnerPath],
      env: environment,
      cwd: plan.dsh.workingDirectory,
      toolCallTimeoutMs: plan.dsh.toolCallTimeoutMilliseconds,
      failOnStartupError: true,
      reconnect: {
        enabled: plan.dsh.reconnect.enabled,
        initialDelayMs: plan.dsh.reconnect.initialDelayMilliseconds,
        maxDelayMs: plan.dsh.reconnect.maximumDelayMilliseconds,
        maxAttempts: plan.dsh.reconnect.maximumAttempts
      }
    });
  }
}

export { Config, apply, inject, name };
