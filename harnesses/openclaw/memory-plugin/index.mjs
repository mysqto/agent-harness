// Recall for this harness: a `before_prompt_build` hook that asks the deployment's own memory
// service what it remembers and prepends the answer to the turn's context.
//
// It composes nothing and decides nothing. `yaam-read bundle` is the endpoint that exists to compose
// context for one request, and what it returns is record *structure* — frontmatter fields, never a
// body — so what this injects is a compact rendering of that structure. There is no summarisation
// step and no model in this path: a model here would be a second opinion about records the service
// already ranked, paid for in front of every reply.
//
// **Every failure lets the turn through, and that is the opposite of the tool-policy plugin beside
// it.** A guard that cannot decide must block, because "we could not tell" and "it was fine" are
// different answers and only one is safe. A memory lookup that cannot answer must not block, because
// an agent that stops working when its memory service is down is worse than an agent with no memory.
// So a reader that is unconfigured, unspawnable, slow, or answering something unreadable produces no
// context and a warning — never an error the host has to decide about.
//
// The one thing that must not blur is *which* of those happened. "The service matched nothing" and
// "the service could not be asked" call for opposite reactions, so they are separate outcomes here
// and separate lines in the log.
//
// # What this can tell a bundle about the turn
//
// A bundle composes context out of *entities* and an *actor*, so a caller that can name neither gets
// whatever its actor happened to write — and where nothing was ever written under that name, an
// empty answer every turn that looks exactly like a quiet store. The actor alone was this plugin's
// first version, and that is the shape of hole it left.
//
// Two things the host does hand a `before_prompt_build` handler, and both become lookups:
//
//   - **the conversation**, out of `ctx.channelId`. The host derives that from the session key, and
//     for a threaded run it carries the thread inside it. See `threadOf`.
//   - **the message**, as `event.prompt`. It goes to the reader's own read-time entity inference,
//     which turns prose into lookup keys.
//
// Neither is a guess this file makes about what the answer should contain. A lookup key that names
// nothing matches nothing; the deployment's own rules decide what a key even is.

import { spawn } from "node:child_process";

const PLUGIN_ID = "harness-memory";

/** The read shape this injects. Any other shape is a misconfiguration, not a variation. */
const READ_SHAPE = "bundle";

/**
 * How the host spells "and this run is inside a thread" in a conversation id.
 *
 * The one shape here that is the harness's rather than this deployment's: `ctx.channelId` is built
 * from the session key, and a threaded run's key ends `…:thread:<id>`. It is the only route from
 * this hook to the thread — the payload carries no thread field, and nothing else in the context
 * names one.
 *
 * A harness that changed this spelling would leave recall quiet rather than broken, which is why a
 * turn that yields no thread is reported rather than passed over in silence.
 */
const THREAD_MARKER = ":thread:";

/**
 * Most of the message handed to read-time inference.
 *
 * The tail of it, because the host prefixes history and envelope formatting to `event.prompt` and
 * what this turn is actually about is at the end. A cap at all because this becomes one argument in
 * an argument list, which has a length the operating system enforces and nothing here would survive.
 */
const MAX_INFER_CHARS = 4000;

/** How long the whole lookup gets, in front of a reply. */
const DEFAULT_TIMEOUT_MS = 5000;

/** Most records one turn may carry, and the reader's `--limit`. */
const DEFAULT_MAX_RECORDS = 8;

/** Ceiling on the rendered block. */
const DEFAULT_MAX_CHARS = 2000;

/** Cap on what is read from the reader's streams, so a wedged reader cannot grow this process. */
const STDOUT_CAP = 262_144;
const STDERR_CAP = 4096;

/** What the injected block says it is. The model is told the shape it is getting, not just the text. */
const HEADING =
  "Recalled from this deployment's memory. Record structure only — these are frontmatter fields, " +
  "not the records' contents.";

/**
 * The bounds this plugin adds to the configured argv.
 *
 * Nested innermost-first on purpose: the service is given a deadline shorter than the socket wait,
 * and the socket wait is shorter than the budget this kills the process at. So the most specific
 * answer available is the one that lands — the service naming the source it could not consult, or
 * the reader naming the socket that went quiet, rather than this file's generic "no answer".
 *
 * An operator who already named one of these keeps it: a bound in the config was chosen for a reason
 * this file cannot see.
 */
function bounds(argv, budgetMs, maxRecords) {
  const extra = [];
  const named = (flag) => argv.includes(flag);
  if (!named("--limit")) extra.push("--limit", String(maxRecords));
  if (!named("--deadline-ms")) extra.push("--deadline-ms", String(Math.max(1, Math.floor(budgetMs * 0.5))));
  if (!named("--timeout-ms")) extra.push("--timeout-ms", String(Math.max(1, Math.floor(budgetMs * 0.8))));
  return extra;
}

/**
 * The actor whose recent activity a turn asks about, when the config left it open.
 *
 * The socket is evidence of who is *asking*; the actor says whose activity to gather, and the host
 * knows that per run. Refused when it could be read as a flag — this goes into an argument list, and
 * a value starting with `-` would be parsed as one.
 */
function actorFor(argv, agentId) {
  if (argv.includes("--actor")) return [];
  if (typeof agentId !== "string") return [];
  const trimmed = agentId.trim();
  if (!trimmed || trimmed.startsWith("-")) return [];
  return ["--actor", trimmed];
}

/**
 * The conversation this turn belongs to, as an entity identifier, or nothing.
 *
 * `ctx.channelId` is the host's resolved conversation id. For a threaded run it reads
 * `<conversation><THREAD_MARKER><thread>`, and the identifier a record joins on puts those two
 * either side of a `/` — so this is a re-spelling, not a derivation.
 *
 * Nothing is returned for a run that is not in a thread. That is the ordinary case for a direct
 * message, and it is an absence rather than a fault: a conversation id with no thread in it names
 * the conversation, and this plugin has no basis for deciding that a whole conversation is the unit
 * a deployment files records under.
 *
 * **The host case-folds the conversation half** for every provider but a couple, so an identifier
 * that reaches a record with its original case will not match one built here. That is a fact about
 * the deployment's own `entities.yaml` — the kind's normalisation is where the two are reconciled —
 * and not something this file can paper over without inventing a case it was not given.
 */
function threadOf(channelId) {
  if (typeof channelId !== "string") return undefined;
  const at = channelId.indexOf(THREAD_MARKER);
  if (at <= 0) return undefined;
  const conversation = channelId.slice(0, at);
  const thread = channelId.slice(at + THREAD_MARKER.length);
  // A comma is how a bundle separates its entity terms, so one inside an identifier arrives as two
  // and the reader refuses the whole read. Dropped instead: a turn still recalls what it can.
  if (!thread || conversation.includes(",") || thread.includes(",")) return undefined;
  return `${conversation}/${thread}`;
}

/**
 * What one turn knows about itself, read off the hook's own payload.
 *
 * Separated from the lookup so that "what the host gives us" is one function with one place to look
 * when a harness upgrade changes it. `event` carries `prompt` and `messages` and nothing else;
 * `ctx` carries identifiers and no content.
 */
function turnOf(settings, event, ctx) {
  const kind = typeof settings?.threadEntity === "string" ? settings.threadEntity.trim() : "";
  const thread = kind ? threadOf(ctx?.channelId ?? ctx?.chatId) : undefined;
  const prompt = typeof event?.prompt === "string" ? event.prompt.trim() : "";
  return {
    agentId: ctx?.agentId,
    entities: thread ? [`${kind}:${thread}`] : [],
    text: prompt ? prompt.slice(-MAX_INFER_CHARS) : undefined,
  };
}

/**
 * The entities this turn can name outright.
 *
 * `--entity=` rather than two arguments, here and below, because these values come from a
 * conversation: one that began with a `-` would be read as a flag, and a turn is not the place to
 * discover that.
 */
function entitiesFor(argv, entities) {
  if (argv.includes("--entity")) return [];
  return entities.map((entity) => `--entity=${entity}`);
}

/**
 * The message, and the rules to read it with.
 *
 * Both or neither: the reader refuses one without the other, and rightly — text nobody read, and
 * rules nothing was read with, are each a narrower bundle than was asked for. So a deployment that
 * configured no `specDir`, and a turn that arrived with no message, both add nothing here rather
 * than half of something.
 *
 * What this buys is the other half of the hole the actor left. The reader's inference turns prose
 * into lookup keys, and a key that names nothing matches nothing — so the bar a *writer* has to
 * clear before it may infer a reference does not apply, and this may hand over whatever the rules
 * support.
 */
function inferenceFor(argv, specDir, text) {
  if (!text || typeof specDir !== "string" || !specDir.trim()) return [];
  if (argv.includes("--infer-entities") || argv.includes("--infer-from")) return [];
  return [`--infer-entities=${specDir.trim()}`, `--infer-from=${text}`];
}

/** Reads this plugin's own settings out of the harness config. */
function settingsFrom(config) {
  const entry = config?.plugins?.entries?.[PLUGIN_ID];
  return (entry && typeof entry === "object" ? entry.config : undefined) ?? {};
}

/** A positive integer setting, or the default when the config says nothing usable. */
function positive(value, fallback) {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

/**
 * Renders one record's structure as a single line.
 *
 * Field order is fixed rather than whatever the JSON iterated: two turns recalling the same record
 * must produce the same text, or a provider's prompt cache never hits.
 */
function line(record) {
  const parts = [`at=${record?.received_at ?? record?.at ?? "?"}`];
  if (record?.action) parts.push(`action=${record.action}`);
  if (record?.outcome) parts.push(`outcome=${record.outcome}`);
  if (record?.agent) parts.push(`agent=${record.agent}`);
  const entities = Array.isArray(record?.entities)
    ? record.entities.map((entity) => `${entity?.kind ?? "?"}:${entity?.id ?? "?"}`)
    : [];
  if (entities.length > 0) parts.push(`entities=${entities.join(",")}`);
  const attrs = record?.attrs && typeof record.attrs === "object" ? record.attrs : {};
  const rendered = Object.keys(attrs)
    .sort()
    .map((key) => `${key}=${String(attrs[key])}`);
  if (rendered.length > 0) parts.push(`attrs=${rendered.join(" ")}`);
  if (Array.isArray(record?.tags) && record.tags.length > 0) parts.push(`tags=${record.tags.join(",")}`);
  return `- ${parts.join(" ")}`;
}

/**
 * Turns one bundle into the block a turn carries.
 *
 * Whatever is cut is counted. A capped list that reads as the whole truth is the failure this is
 * guarding against: the model would treat "eight records" as "everything there is", and act on it.
 */
function renderContext(answer, limits) {
  const records = Array.isArray(answer?.records) ? answer.records : [];
  if (records.length === 0) return "";

  const kept = records.slice(0, limits.maxRecords);
  const lines = [];
  let used = 0;
  for (const record of kept) {
    const rendered = line(record);
    if (used + rendered.length > limits.maxChars) break;
    lines.push(rendered);
    used += rendered.length + 1;
  }
  if (lines.length === 0) return "";

  const dropped = records.length - lines.length;
  const notes = [];
  if (dropped > 0) notes.push(`${dropped} further record(s) matched and are not shown.`);
  if (answer?.degraded === true) {
    const omitted = Array.isArray(answer.omitted) ? answer.omitted.filter((entry) => typeof entry === "string") : [];
    notes.push(
      `This is partial: ${omitted.length > 0 ? omitted.join("; ") : "a source was not consulted in time"}. ` +
        "Safe to answer a question from, not safe to act on.",
    );
  }
  return [HEADING, ...lines, ...notes].join("\n");
}

/** The reason a lookup could not be made at all, decided before anything is spawned. */
function unusable(argv) {
  if (!Array.isArray(argv) || argv.length === 0) {
    return (
      `no reader is configured, so nothing can be recalled. Set ` +
      `plugins.entries.${PLUGIN_ID}.config.read to the reader argv.`
    );
  }
  if (!argv.includes(READ_SHAPE)) {
    return (
      `the configured reader does not name the "${READ_SHAPE}" read, and that is the only shape this ` +
      `injects: it is the read that composes context for one request and reports when it is partial.`
    );
  }
  return undefined;
}

/**
 * Asks the memory service what it remembers.
 *
 * `turn` is what this turn could say about itself — see `turnOf`. Every part of it is optional: a
 * bundle with no entity and no actor is a legitimate, and empty, question.
 *
 * Resolves to one of three outcomes and never rejects: `recalled` with a rendered block, `empty`
 * when the service answered and matched nothing, `unavailable` with a reason when it could not be
 * asked. The caller turns those into an injection and a log line; nothing downstream has to infer
 * which happened from an absent result.
 */
async function recall(settings, turn) {
  const argv = settings?.read;
  const budgetMs = positive(settings?.timeoutMs, DEFAULT_TIMEOUT_MS);
  const limits = {
    maxRecords: positive(settings?.maxRecords, DEFAULT_MAX_RECORDS),
    maxChars: positive(settings?.maxChars, DEFAULT_MAX_CHARS),
  };
  // What the turn named, kept for the log. Not what the reader *inferred* from the message: that is
  // decided inside the reader by the deployment's own rules, and this process never sees the keys it
  // produced.
  const named = turn?.entities ?? [];

  const why = unusable(argv);
  if (why) return { kind: "unavailable", why, asked: named };

  const args = [
    ...argv.slice(1),
    ...entitiesFor(argv, named),
    ...inferenceFor(argv, settings?.specDir, turn?.text),
    ...actorFor(argv, turn?.agentId),
    ...bounds(argv, budgetMs, limits.maxRecords),
  ];

  return new Promise((resolve) => {
    let settled = false;
    const answer = (outcome) => {
      if (settled) return;
      settled = true;
      // Every outcome carries what was asked about, so the log can say whether an empty answer was
      // a quiet store or a turn that had nothing to ask with.
      resolve({ ...outcome, asked: named });
    };
    const failed = (reason) => answer({ kind: "unavailable", why: reason });

    let child;
    try {
      child = spawn(argv[0], args, { stdio: ["ignore", "pipe", "pipe"] });
    } catch (error) {
      failed(`the reader could not be started: ${error?.message ?? error}`);
      return;
    }

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      failed(`the reader did not answer within ${budgetMs}ms`);
    }, budgetMs);

    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk) => {
      if (stdout.length < STDOUT_CAP) stdout += String(chunk);
    });
    child.stderr?.on("data", (chunk) => {
      if (stderr.length < STDERR_CAP) stderr += String(chunk);
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      failed(`the reader could not be started: ${error?.message ?? error}`);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      // The reader exits non-zero for every answer that is not a `2xx`, and prints why. An empty
      // match is not one of those: it is a `200` with no rows, and it exits 0.
      if (code !== 0) {
        failed(stderr.trim().split("\n")[0] || `the reader exited ${code}`);
        return;
      }
      let parsed;
      try {
        parsed = JSON.parse(stdout);
      } catch {
        failed("the reader's answer was not readable as JSON");
        return;
      }
      if (!Array.isArray(parsed?.records)) {
        failed("the reader answered a shape with no records in it");
        return;
      }
      if (parsed.records.length === 0) {
        answer({ kind: "empty" });
        return;
      }
      const context = renderContext(parsed, limits);
      if (!context) {
        // Records matched, and not one of them fit the ceiling. Distinct from an empty match: the
        // fix is a bigger ceiling, not a fuller store.
        failed(`${parsed.records.length} record(s) matched and none fit within ${limits.maxChars} characters`);
        return;
      }
      answer({
        kind: "recalled",
        context,
        count: parsed.records.length,
        degraded: parsed.degraded === true,
        tokenEstimate: Number.isFinite(parsed.token_estimate) ? parsed.token_estimate : undefined,
      });
    });
  });
}

/** What the host is told, given an outcome. Only a recall injects; the other two inject nothing. */
function injectionFrom(outcome) {
  return outcome?.kind === "recalled" ? { prependContext: outcome.context } : undefined;
}

/**
 * Says which of the three happened, at the level that matches.
 *
 * A quiet store and a broken lookup are one word apart in the log on purpose: `matched nothing` is
 * a fact about the store, `recall unavailable` is a fact about the plumbing, and a deployment that
 * cannot tell them apart cannot tell a quiet week from an outage.
 */
function report(outcome, logger) {
  if (outcome?.kind === "recalled") {
    const cost = outcome.tokenEstimate === undefined ? "" : `, ~${outcome.tokenEstimate} tokens`;
    logger?.info?.(
      `${PLUGIN_ID}: recalled ${outcome.count} record(s)${outcome.degraded ? " (partial)" : ""}${cost}`,
    );
    return;
  }
  if (outcome?.kind === "empty") {
    // Named, because the first question about an empty answer is what was asked. A turn that could
    // name no entity at all reads as `about nothing in particular`, and that is a different problem
    // from a store with nothing in it — the fix for one is the wiring, for the other is time.
    const about = outcome.asked?.length ? outcome.asked.join(", ") : "nothing in particular";
    logger?.info?.(
      `${PLUGIN_ID}: the memory service matched nothing (asked about ${about}); the turn proceeds with no recalled context`,
    );
    return;
  }
  logger?.warn?.(
    `${PLUGIN_ID}: recall unavailable, the turn proceeds without memory: ${outcome?.why ?? "no reason given"}`,
  );
}

export default {
  id: PLUGIN_ID,
  name: "Harness memory recall",
  description: "Recalls what this deployment remembers and prepends its structure to a turn's context.",
  // Declared here as well as in the manifest, and they must agree: the loader takes the export's
  // word for it and warns about the mismatch, and a plugin the slot names but that is not of this
  // kind may register nothing memory-shaped.
  kind: "memory",
  register(api) {
    const settings = settingsFrom(api?.config);

    // Said once at load, because a per-turn warning is easy to lose in a busy log and this one is
    // about the wiring rather than about a turn.
    const why = unusable(settings.read);
    if (why) api?.logger?.warn?.(`${PLUGIN_ID}: ${why}`);

    // The two optional halves, said once each. Neither is a fault — a deployment may want the actor
    // alone — but each is the difference between a bundle that can name this turn and one that
    // cannot, and an operator wondering why recall is thin should not have to read this file to
    // find out which halves are wired.
    for (const [setting, absent] of [
      ["threadEntity", "no thread is looked up: set config.threadEntity to the entity kind this deployment files conversations under"],
      ["specDir", "the message is not read for entities: set config.specDir to the deployment's spec directory"],
    ]) {
      if (typeof settings[setting] !== "string" || !settings[setting].trim()) {
        api?.logger?.info?.(`${PLUGIN_ID}: ${absent}`);
      }
    }

    const budgetMs = positive(settings.timeoutMs, DEFAULT_TIMEOUT_MS);

    // Bounded twice, and the outer bound is this plugin's to lose. The host does default this hook
    // to 15s — unlike the tool-call hook next door, which has no default at all — but 15s in front
    // of a reply is a conversation that looks hung, so a shorter budget is always passed. It is
    // deliberately longer than the one the lookup enforces on itself: that way the answer that
    // lands is this file's, which says whether the store was quiet or the reader was, rather than
    // the host's generic "the hook failed".
    api.on(
      "before_prompt_build",
      async (event, ctx) => {
        const outcome = await recall(settings, turnOf(settings, event, ctx));
        report(outcome, api?.logger);
        return injectionFrom(outcome);
      },
      { timeoutMs: budgetMs * 2 },
    );
  },
};

// Exported for tests: the outcome path is worth exercising without a gateway around it.
export {
  recall,
  renderContext,
  injectionFrom,
  report,
  bounds,
  actorFor,
  entitiesFor,
  inferenceFor,
  threadOf,
  turnOf,
  settingsFrom,
  unusable,
  PLUGIN_ID,
  READ_SHAPE,
  THREAD_MARKER,
  MAX_INFER_CHARS,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_MAX_RECORDS,
  DEFAULT_MAX_CHARS,
  HEADING,
};
