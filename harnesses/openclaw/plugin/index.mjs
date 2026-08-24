// Layer 2 for this harness: a `before_tool_call` hook that hands the call to `harness-guard` and
// refuses whatever the guard refuses.
//
// It decides nothing. The guard reads spec/tool-policy.json and answers with an exit code; this file
// only moves JSON in one direction and a refusal back in the other. That is why the whole plugin is
// this short, and why adding a rule never means editing it.
//
// Every failure blocks. A guard that cannot be spawned, a guard that times out and a guard that
// refuses are the same answer here, because "we could not tell" and "it was fine" are different
// things and only one of them is safe.

import { spawn } from "node:child_process";

const PLUGIN_ID = "harness-tool-policy";

/** The guard's exit code for a refusal. Anything non-zero blocks; this one is expected. */
const BLOCK = 2;

/** How long the guard gets before the call is refused for want of an answer. */
const DEFAULT_TIMEOUT_MS = 5000;

/**
 * Runs the guard over one tool call.
 *
 * Resolves to a blocking result, or `undefined` to let the call through. Never rejects: a rejected
 * promise is a hook the host has to decide about, and this file is the one place that decision is
 * already made.
 */
async function consult(argv, timeoutMs, event, logger) {
  if (!Array.isArray(argv) || argv.length === 0) {
    return {
      block: true,
      blockReason:
        `${PLUGIN_ID}: no guard is configured, so no tool call can be checked. ` +
        `Set plugins.entries.${PLUGIN_ID}.config.guard to the guard argv.`,
    };
  }

  // Only the fields the translator reads. Sending the whole event would put conversation content
  // into a subprocess argument list for no benefit.
  const payload = JSON.stringify({
    toolName: event?.toolName,
    params: event?.params ?? {},
    derivedPaths: event?.derivedPaths ?? [],
  });

  return new Promise((resolve) => {
    let settled = false;
    const answer = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    let child;
    try {
      child = spawn(argv[0], argv.slice(1), { stdio: ["pipe", "ignore", "pipe"] });
    } catch (error) {
      answer(refusal(`the guard could not be started: ${error?.message ?? error}`));
      return;
    }

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      answer(refusal(`the guard did not answer within ${timeoutMs}ms`));
    }, timeoutMs);

    let stderr = "";
    child.stderr?.on("data", (chunk) => {
      // Bounded: a wedged guard printing without end must not grow this process's memory.
      if (stderr.length < 4096) stderr += String(chunk);
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      answer(refusal(`the guard could not be started: ${error?.message ?? error}`));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) {
        answer(undefined);
        return;
      }
      const reason = stderr.trim() || `the guard exited ${code}`;
      if (code !== BLOCK) {
        // Still a block, but worth saying: an unexpected code usually means a broken install rather
        // than a denied call, and the two need different fixes.
        logger?.warn?.(`${PLUGIN_ID}: guard exited ${code}, expected 0 or ${BLOCK}`);
      }
      answer({ block: true, blockReason: reason });
    });

    child.stdin?.on("error", () => {
      // The guard exited before reading stdin. `close` decides; this only stops an unhandled throw.
    });
    child.stdin?.end(payload);
  });
}

function refusal(why) {
  return { block: true, blockReason: `${PLUGIN_ID}: ${why}` };
}

/** Reads this plugin's own settings out of the harness config. */
function settingsFrom(config) {
  const entry = config?.plugins?.entries?.[PLUGIN_ID];
  return (entry && typeof entry === "object" ? entry.config : undefined) ?? {};
}

export default {
  id: PLUGIN_ID,
  name: "Harness tool policy",
  description: "Refuses a tool call the declared tool policy denies.",
  register(api) {
    const settings = settingsFrom(api?.config);
    const argv = settings.guard;
    const timeoutMs =
      Number.isInteger(settings.timeoutMs) && settings.timeoutMs > 0
        ? settings.timeoutMs
        : DEFAULT_TIMEOUT_MS;

    // A hook timeout on the host's side would let the call through, so the budget given to the host
    // is deliberately longer than the one this handler enforces on itself.
    api.hooks.on(
      "before_tool_call",
      (event) => consult(argv, timeoutMs, event, api.logger),
      { timeoutMs: timeoutMs * 2 },
    );
  },
};

// Exported for tests: the decision path is worth exercising without a gateway around it.
export { consult, settingsFrom, PLUGIN_ID, DEFAULT_TIMEOUT_MS };
