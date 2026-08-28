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
//
// # And one thing that is not about the turn at all
//
// A third read runs on the turn that opens a session, and only there: a date-grouped digest of what
// this deployment recorded lately. It is the one piece of recall nobody asked for, which is exactly
// why it is fenced — see `digestPlan` for when it declines, and `DIGEST_HEADING` for the claim it
// makes, which is weaker again than a ranked search hit because it is not a claim about this message.

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

/** The read shape the fallback uses when the bundle matched nothing. */
const SEARCH_SHAPE = "search";

/**
 * The read shape the session-opening digest uses.
 *
 * `records` and not `bundle` or `history`, because a digest is the one question here with no key in
 * it: not "what is filed under this" but "what happened lately, by anyone". `records` is the only
 * read that takes a window and no entity, which is the same shape the question has.
 */
const DIGEST_SHAPE = "records";

/** Rows a digest may carry, and its `--limit`. Wider than recall's page: it is a list, not an answer. */
const DEFAULT_DIGEST_MAX_RECORDS = 12;

/** Ceiling on the rendered digest, deliberately below recall's. */
const DEFAULT_DIGEST_MAX_CHARS = 1200;

/** One day, in the milliseconds the window flags are spelled in. */
const DAY_MS = 86_400_000;

/**
 * How little of the budget is still worth a digest.
 *
 * The same floor the fallback has, for the same reason: all three reads share one deadline, and the
 * digest is the last of them to ask. Nothing that arrives unasked-for may extend a wait somebody
 * else's question is already spending.
 */
const MIN_DIGEST_MS = 600;

/**
 * Sessions this process has already offered a digest to.
 *
 * Process memory, and the honest statement about it is that a gateway restart forgets: a session
 * running across one gets offered a second digest. That is one extra block on one turn, which is the
 * cheap direction to be wrong in — the expensive one is a digest on every turn, and the payload
 * signal in `claimOpening` is what rules that out independently of this map.
 *
 * Bounded, because a gateway that never restarts talks to an unbounded number of conversations.
 * Evicting the oldest key can only cause a re-offer, never a repeat within a session.
 */
const SEEN_SESSIONS = new Map();
const MAX_SEEN_SESSIONS = 512;

/**
 * Most terms one fallback needle carries.
 *
 * A needle is an OR of quoted words, and every extra word widens what ranks. Enough for a question
 * a person asked; short of turning a pasted log into a query.
 */
const MAX_SEARCH_TERMS = 12;

/** Shortest word worth searching for. Below this a token is punctuation or an article. */
const MIN_TERM_CHARS = 3;

/**
 * Words dropped from a needle.
 *
 * Not a general stoplist: full-text ranking already discounts what is common. These are the words
 * that turn up in the *framing* of a question rather than its subject, so an OR containing them
 * ranks every record that ever used them alongside the one the question is about.
 */
const SEARCH_STOPWORDS = new Set([
  "the", "and", "for", "with", "you", "your", "what", "when", "where", "which", "who", "why", "how",
  "any", "are", "was", "were", "has", "have", "had", "did", "does", "can", "could", "would", "should",
  "this", "that", "these", "those", "there", "here", "about", "from", "into", "our", "know",
  "knowledge", "memory", "remember", "anything", "something", "please", "tell", "give", "get",
]);

/**
 * How little of the budget is still worth a second lookup.
 *
 * The fallback shares one deadline with the bundle rather than getting its own: the outer bound this
 * hook registers is what stands between recall and a reply that looks hung, and a fallback that
 * could double the wait would spend a bound someone else set.
 */
const MIN_FALLBACK_MS = 600;

/** What the injected block says it is. The model is told the shape it is getting, not just the text. */
const HEADING =
  "Recalled from this deployment's memory. Record structure only — these are frontmatter fields, " +
  "not the records' contents.";

/**
 * What the fallback's block says it is, and it says something different on purpose.
 *
 * A bundle is composed: the service gathered records around keys and reports when the gathering was
 * partial. A search is ranked: these records contain words from the question, which is a weaker
 * claim, and a model told otherwise would present a keyword hit as an established connection.
 */
const SEARCH_HEADING =
  "Found by searching this deployment's memory for words in this message — these records mention " +
  "them and may not be about them. Record structure only, not the records' contents.";

/**
 * What the digest's block says it is, and it is the weakest of the three claims on purpose.
 *
 * The other two answer the turn: one composed around its keys, one ranked on its words. This one was
 * not asked for and is not about the message at all — so it says so first, before a model reads a
 * list of recent work as background it is expected to have used.
 *
 * The second sentence is the limitation, stated rather than papered over. Every read in this
 * deployment returns frontmatter, so a digest can say that an agent deployed something on Tuesday and
 * which commit it named. It cannot say what the deploy was for, what went wrong, or what anyone
 * concluded. A model that treats these lines as a summary of recent events will overstate them, and
 * the only defence against that is the heading saying what they are.
 */
const DIGEST_HEADING =
  "Recent activity in this deployment's memory, grouped by date. This is background, not an answer: " +
  "nobody asked for it and none of it is necessarily about this message. Record structure only — " +
  "who acted, when, and what they referenced. It does not say what any of it was about, and this " +
  "store holds no prose that could.";

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
 * What names this session, out of the identifiers the host hands over.
 *
 * In preference order, because they narrow differently: `sessionKey` is the host's own name for the
 * run's session and is what a restart resumes under; `sessionId` identifies the same thing where the
 * key is absent; the conversation ids are a fallback that groups a whole channel rather than a
 * session, which is coarser than wanted and still bounded — a coarse key offers *fewer* digests, not
 * more.
 *
 * Nothing is returned when the payload names none of them, and a turn that cannot be told apart from
 * the next one is never treated as an opening. Injecting on a turn this cannot identify is precisely
 * the every-turn cost the digest exists inside a fence to avoid.
 */
function sessionOf(ctx) {
  for (const value of [ctx?.sessionKey, ctx?.sessionId, ctx?.channelId, ctx?.chatId]) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

/**
 * Whether this turn is the one that opens its session — asked once, and answered once.
 *
 * **`before_prompt_build` fires every turn, and the payload has no "session started" field.** What it
 * does have is `event.messages`: the session's prepared history, which the host passes beside
 * `event.prompt` rather than including this turn in. An empty history is the session's first turn.
 * That is the honest signal, read off the payload rather than inferred from the clock.
 *
 * It is not trusted alone. One of this harness's backends builds that array per run and appends to it
 * as the run proceeds, so an empty history there is the first *hook call* rather than the first turn
 * — which would put a digest in front of every message. So the payload signal is intersected with
 * process memory of the sessions already offered one, and both must agree.
 *
 * Claiming is the point: this marks the session seen whether or not a digest is ultimately built, so
 * the offer is made once and a turn that declined it does not hand the offer to the turn after. What
 * a restart forgets is one re-offer, and `SEEN_SESSIONS` says why that is the cheap direction.
 */
function claimOpening(event, ctx) {
  const session = sessionOf(ctx);
  if (!session) return false;
  const first = Array.isArray(event?.messages) && event.messages.length === 0;
  const seen = SEEN_SESSIONS.has(session);
  if (!seen) {
    if (SEEN_SESSIONS.size >= MAX_SEEN_SESSIONS) {
      SEEN_SESSIONS.delete(SEEN_SESSIONS.keys().next().value);
    }
    SEEN_SESSIONS.set(session, true);
  }
  return first && !seen;
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
    // Claimed here rather than in the lookup, because this is the one function that sees the payload
    // and the claim has to happen once per turn however the lookup then goes.
    opening: claimOpening(event, ctx),
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
function renderContext(answer, limits, heading = HEADING) {
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
  return [heading, ...lines, ...notes].join("\n");
}

/**
 * The date a record belongs to, for grouping, or nothing.
 *
 * The first ten characters of the server-stamped timestamp, which is a date in the store's own
 * spelling rather than one this file computed. Computing one would mean choosing a timezone, and a
 * digest that quietly re-dated a record into yesterday would be wrong in the one field a reader
 * scanning by date is relying on.
 */
function dayOf(record) {
  const at = record?.received_at ?? record?.at;
  if (typeof at !== "string" || at.length < 10) return undefined;
  const day = at.slice(0, 10);
  return /^\d{4}-\d{2}-\d{2}$/.test(day) ? day : undefined;
}

/**
 * One record's structure as a digest line: everything `line` renders except the timestamp.
 *
 * The date is the group it sits under, so repeating it on every row would spend the budget saying
 * what the heading above already said. Field order is fixed for the same reason it is in `line`.
 */
function digestLine(record) {
  const parts = [];
  if (record?.action) parts.push(`action=${record.action}`);
  if (record?.outcome) parts.push(`outcome=${record.outcome}`);
  if (record?.agent) parts.push(`agent=${record.agent}`);
  const entities = Array.isArray(record?.entities)
    ? record.entities.map((entity) => `${entity?.kind ?? "?"}:${entity?.id ?? "?"}`)
    : [];
  if (entities.length > 0) parts.push(`entities=${entities.join(",")}`);
  if (Array.isArray(record?.tags) && record.tags.length > 0) parts.push(`tags=${record.tags.join(",")}`);
  return parts.length > 0 ? `  - ${parts.join(" ")}` : undefined;
}

/**
 * A window of records as a date-grouped block, or nothing.
 *
 * Grouped by date because that is the axis a person scanning "what has been happening" reads on, and
 * because it is the one axis this store can render without a body: the date is stamped, the actor is
 * signed for, and the reference was stated. Nothing here is derived.
 *
 * Whatever is cut is counted, exactly as `renderContext` counts it. A digest is more likely to be cut
 * than a bundle — it is a window rather than a match — so a list that read as the whole window would
 * be the more misleading of the two.
 */
function renderDigest(answer, limits, days) {
  const records = Array.isArray(answer?.records) ? answer.records : [];
  if (records.length === 0) return "";

  const groups = [];
  const byDay = new Map();
  let used = 0;
  let shown = 0;
  for (const record of records.slice(0, limits.maxRecords)) {
    const rendered = digestLine(record);
    if (!rendered) continue;
    const day = dayOf(record) ?? "undated";
    const heading = byDay.has(day) ? 0 : day.length + 1;
    if (used + heading + rendered.length > limits.maxChars) break;
    if (!byDay.has(day)) {
      const bucket = [];
      byDay.set(day, bucket);
      groups.push([day, bucket]);
    }
    byDay.get(day).push(rendered);
    used += heading + rendered.length + 1;
    shown += 1;
  }
  if (shown === 0) return "";

  const lines = [];
  for (const [day, rows] of groups) lines.push(day, ...rows);
  const dropped = records.length - shown;
  const notes = [`Window: the last ${days} day(s).`];
  if (dropped > 0) notes.push(`${dropped} further record(s) in that window are not shown.`);
  return [DIGEST_HEADING, ...lines, notes.join(" ")].join("\n");
}

/**
 * What the search read is bounded by, which is not what the bundle is bounded by.
 *
 * Two of the bundle's three bounds and not the third: `--deadline-ms` is the deadline the *service*
 * applies while gathering a bundle's sources, and the search read has no such flag. Passing it
 * anyway is a usage error, and a usage error here is a fallback that never once succeeded while
 * every fake reader in the test suite accepted it happily.
 */
function searchBounds(argv, budgetMs, maxRecords) {
  const extra = [];
  const named = (flag) => argv.includes(flag);
  if (!named("--limit")) extra.push("--limit", String(maxRecords));
  if (!named("--timeout-ms")) extra.push("--timeout-ms", String(Math.max(1, Math.floor(budgetMs * 0.8))));
  return extra;
}

/**
 * The same reader and socket, asked for the search shape instead of the bundle.
 *
 * Derived from the configured argv rather than configured separately: the two reads differ by one
 * word, and a second argv to keep in step is a second thing to get wrong — a fallback pointed at
 * another socket would answer from another store without saying so.
 *
 * Returns nothing when the configured argv does not name the bundle shape, which `unusable` has
 * already refused by then.
 */
function searchArgv(argv) {
  return shapeArgv(argv, SEARCH_SHAPE);
}

/** The same reader and socket, asked for the digest's window read. See `searchArgv`. */
function digestArgv(argv) {
  return shapeArgv(argv, DIGEST_SHAPE);
}

/** The configured argv with its read shape replaced, or nothing when it names no shape to replace. */
function shapeArgv(argv, shape) {
  const at = argv.indexOf(READ_SHAPE);
  if (at < 0) return undefined;
  const swapped = argv.slice();
  swapped[at] = shape;
  return swapped;
}

/**
 * What the digest read is bounded by.
 *
 * The search read's two flags and not the bundle's three, for the same reason: `--deadline-ms` is a
 * bundle's flag for the deadline the service applies while gathering sources, and `records` has no
 * such flag. Passing it is a usage error the real reader refuses and every fake reader accepts, which
 * is the failure mode that shipped once here already.
 */
function digestBounds(argv, budgetMs, maxRecords) {
  const extra = [];
  const named = (flag) => argv.includes(flag);
  if (!named("--limit")) extra.push("--limit", String(maxRecords));
  if (!named("--timeout-ms")) extra.push("--timeout-ms", String(Math.max(1, Math.floor(budgetMs * 0.8))));
  return extra;
}

/**
 * The digest read, or nothing when it declines — which is the ordinary case for nearly every turn.
 *
 * Five ways to decline, and the first two are the fence:
 *
 *   - **The config did not ask for one.** Off unless `digestDays` names a window. A deployment whose
 *     records are all one shape gets a block that reads as noise, and noise costs the same tokens as
 *     signal; that judgement belongs to the operator who can see the store.
 *   - **This is not the turn that opens the session.** See `claimOpening`. Without this the block
 *     goes in front of every message, and recall on this deployment already costs about eleven
 *     hundred tokens a turn.
 *   - **The budget is spent.** The digest shares the deadline the bundle and the fallback share, and
 *     asks last. It is the read most easily done without.
 *   - **The window is not the operator's to be overwritten.** A configured `--from-ms` or `--to-ms`
 *     means somebody chose a window, and half a window is refused by the reader rather than widened.
 *   - **The argv names no shape to swap.** Already refused by `unusable` before this is reached.
 */
function digestPlan(settings, argv, turn, deadline) {
  if (turn?.opening !== true) return undefined;
  // Absent, zero, or anything that is not a whole number of days leaves it off. There is no default
  // window: a window is a judgement about how much history is worth a reader's attention, and this
  // file has never seen the store.
  const days = positive(settings?.digestDays, 0);
  if (days <= 0) return undefined;
  const left = deadline - Date.now();
  if (left < MIN_DIGEST_MS) return undefined;
  const argvDigest = digestArgv(argv);
  if (!argvDigest) return undefined;
  const window = [];
  if (!argvDigest.includes("--from-ms") && !argvDigest.includes("--to-ms")) {
    // Both bounds or neither: the reader refuses one alone, on the grounds that it asks a different
    // question rather than a narrower one.
    const to = Date.now();
    window.push("--from-ms", String(to - days * DAY_MS), "--to-ms", String(to));
  }
  const maxRecords = positive(settings?.digestMaxRecords, DEFAULT_DIGEST_MAX_RECORDS);
  return {
    days,
    args: [...argvDigest.slice(1), ...window, ...digestBounds(argvDigest, left, maxRecords)],
    budgetMs: left,
    limits: {
      maxRecords,
      maxChars: positive(settings?.digestMaxChars, DEFAULT_DIGEST_MAX_CHARS),
    },
  };
}

/**
 * A full-text needle built from the message, or nothing if the message carries no subject.
 *
 * Every word is quoted and the words are OR-ed. Quoting is not cosmetic: the needle is a match
 * expression the index parses, so an unquoted `?` from an ordinary question is a syntax error and
 * the whole read is refused — which is exactly how the first version of this failed.
 *
 * OR rather than AND because this runs only after the bundle matched nothing: the precise question
 * has already been asked and missed, and what is left worth doing is ranking whatever mentions any
 * of these words. The reader's own `--limit` is what keeps that honest.
 */
function needleFrom(text) {
  if (typeof text !== "string") return undefined;
  const seen = new Set();
  const terms = [];
  for (const raw of text.split(/[^A-Za-z0-9_-]+/)) {
    if (terms.length >= MAX_SEARCH_TERMS) break;
    const word = raw.trim();
    if (word.length < MIN_TERM_CHARS) continue;
    const folded = word.toLowerCase();
    if (SEARCH_STOPWORDS.has(folded) || seen.has(folded)) continue;
    seen.add(folded);
    terms.push(`"${word}"`);
  }
  return terms.length > 0 ? terms.join(" OR ") : undefined;
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
 *
 * The digest is a *field* on those outcomes rather than a fourth one, and the budget rule between them
 * is written down here: **a bundle takes the turn, a ranked search does not.**
 *
 * A bundle is the composed answer to the question actually asked, so when it answers, nothing
 * unasked-for goes in beside it and no second read is spent finding out what one would have said.
 * The fallback is a weaker claim by its own heading — records that *mention* the message's words and
 * may not be about them — and a turn holding only that has not had its question answered; it has been
 * handed a rank. Background it can act on is worth more there, not less.
 *
 * That is a decision the measurement made rather than the design. This host prefixes a timestamp to
 * `event.prompt`, so on a live deployment the needle reads `"Fri" OR "2026-08-28" OR "GMT" OR …` and
 * the fallback answers *today's date* on every turn. Under a rule where any recall took the space, a
 * digest would never once have been injected — gated off by a keyword hit on the clock.
 *
 * The cost is that the opening turn can carry both blocks. It is bounded twice — once per session, and
 * by two ceilings that do not share — and the strongest claim is rendered first.
 *
 * The isolation runs both ways, and neither direction is incidental:
 *
 *   - **A digest that fails costs the turn nothing.** A failed digest read leaves the outcome exactly
 *     as recall left it, down to the kind. An empty store stays `empty` — reporting it `unavailable`
 *     because a read nobody asked for did not answer would call a working store broken.
 *   - **A recall that fails does not take the digest with it.** `unavailable` here means the bundle
 *     could not be asked; the window read is a different question over the same socket, and where it
 *     answers, the turn gets a digest and the log still says recall was unavailable.
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

  // One deadline for however many reads happen, so the outer bound this hook registered still means
  // what it says.
  const deadline = Date.now() + budgetMs;

  const outcome = await answerFor(settings, argv, turn, named, limits, budgetMs, deadline);
  // The bundle answered the question. Nothing unasked-for goes in beside it, and no second read is
  // spent finding out what one would have said. A ranked hit does not clear that bar — see above.
  if (outcome.kind === "recalled" && outcome.via === READ_SHAPE) return outcome;
  return withDigest(outcome, settings, argv, turn, deadline);
}

/**
 * The digest read, folded onto whatever recall came back with. Never rejects, never changes the kind.
 *
 * Three shapes of nothing, all of which leave `outcome` untouched: the plan declined, the read
 * failed, or it answered a window with nothing in it. Only the last of those is worth a word in the
 * log at info; the middle one is worth a word too, and neither is worth a warning, because the turn
 * proceeds exactly as it would have.
 */
async function withDigest(outcome, settings, argv, turn, deadline) {
  const plan = digestPlan(settings, argv, turn, deadline);
  if (!plan) return outcome;

  const answer = await once(argv[0], plan.args, plan.budgetMs);
  if (answer.kind === "failed") return { ...outcome, digestFailed: answer.why };
  const context = renderDigest(answer, plan.limits, plan.days);
  if (!context) return { ...outcome, digestEmpty: true, digestDays: plan.days };
  return { ...outcome, digest: context, digestCount: answer.records.length, digestDays: plan.days };
}

/**
 * The two reads that answer the turn: the bundle, then the search that follows an empty one.
 *
 * Split out from `recall` so that "what was asked about this message" is one function and "what is
 * added because the session just opened" is another. They share the deadline and nothing else.
 */
async function answerFor(settings, argv, turn, named, limits, budgetMs, deadline) {
  const args = [
    ...argv.slice(1),
    ...entitiesFor(argv, named),
    ...inferenceFor(argv, settings?.specDir, turn?.text),
    ...actorFor(argv, turn?.agentId),
    ...bounds(argv, budgetMs, limits.maxRecords),
  ];

  const first = await once(argv[0], args, budgetMs);
  if (first.kind === "failed") return { kind: "unavailable", why: first.why, asked: named };
  if (first.records.length > 0) {
    return composed(first, limits, HEADING, { asked: named, via: READ_SHAPE });
  }

  // The bundle answered and matched nothing. Everything below is the second question, and it is a
  // different question: not "what is filed under these keys" but "what mentions these words".
  const fallback = fallbackFor(settings, argv, turn, deadline);
  if (!fallback) return { kind: "empty", asked: named };

  const second = await once(argv[0], fallback.args, fallback.budgetMs);
  // A failed fallback is still an empty bundle, not an outage: the precise read succeeded and found
  // nothing, which is an answer. Reporting it as unavailable would call a working store broken.
  if (second.kind === "failed") {
    return { kind: "empty", asked: named, fallbackFailed: second.why };
  }
  if (second.records.length === 0) return { kind: "empty", asked: named, searched: true };
  return composed(second, limits, SEARCH_HEADING, { asked: named, via: SEARCH_SHAPE });
}

/**
 * The fallback read, or nothing when it is switched off, has no needle, or has no time.
 *
 * Three ways to decline, and each is the ordinary case for some turn: a deployment that wants only
 * what its keys support, a message with no subject in it, and a bundle that used the budget.
 */
function fallbackFor(settings, argv, turn, deadline) {
  if (settings?.searchFallback === false) return undefined;
  const needle = needleFrom(turn?.text);
  if (!needle) return undefined;
  const left = deadline - Date.now();
  if (left < MIN_FALLBACK_MS) return undefined;
  const argvSearch = searchArgv(argv);
  if (!argvSearch) return undefined;
  return {
    args: [
      ...argvSearch.slice(1),
      "--query",
      needle,
      ...searchBounds(argvSearch, left, positive(settings?.maxRecords, DEFAULT_MAX_RECORDS)),
    ],
    budgetMs: left,
  };
}

/** An answer with records in it, rendered — or the failure that none of them fit. */
function composed(answer, limits, heading, extra) {
  const context = renderContext(answer, limits, heading);
  if (!context) {
    // Records matched, and not one of them fit the ceiling. Distinct from an empty match: the fix is
    // a bigger ceiling, not a fuller store.
    return {
      kind: "unavailable",
      why: `${answer.records.length} record(s) matched and none fit within ${limits.maxChars} characters`,
      ...extra,
    };
  }
  return {
    kind: "recalled",
    context,
    count: answer.records.length,
    degraded: answer.degraded === true,
    tokenEstimate: Number.isFinite(answer.token_estimate) ? answer.token_estimate : undefined,
    ...extra,
  };
}

/**
 * One reader invocation, bounded and parsed. Never rejects.
 *
 * Resolves `{kind: "answer", records, degraded, token_estimate}` or `{kind: "failed", why}`. The
 * caller decides what a failure means, because it does not mean the same thing for the read that
 * carries the question and the read that follows it.
 */
function once(argv0, args, budgetMs) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (outcome) => {
      if (settled) return;
      settled = true;
      resolve(outcome);
    };
    const failed = (why) => done({ kind: "failed", why });

    let child;
    try {
      child = spawn(argv0, args, { stdio: ["ignore", "pipe", "pipe"] });
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
      done({ kind: "answer", ...parsed });
    });
  });
}

/**
 * What the host is told, given an outcome.
 *
 * Two blocks may exist and by construction never both do — the digest is only attempted where recall
 * did not recall. Written as a join anyway, because the alternative is a branch that silently drops
 * one of them if that construction is ever changed, and a dropped block is a failure with no symptom.
 */
function injectionFrom(outcome) {
  const blocks = [];
  if (outcome?.kind === "recalled") blocks.push(outcome.context);
  if (typeof outcome?.digest === "string" && outcome.digest) blocks.push(outcome.digest);
  return blocks.length > 0 ? { prependContext: blocks.join("\n\n") } : undefined;
}

/**
 * Says which of the three happened, at the level that matches.
 *
 * A quiet store and a broken lookup are one word apart in the log on purpose: `matched nothing` is
 * a fact about the store, `recall unavailable` is a fact about the plumbing, and a deployment that
 * cannot tell them apart cannot tell a quiet week from an outage.
 */
function report(outcome, logger) {
  reportDigest(outcome, logger);
  if (outcome?.kind === "recalled") {
    const cost = outcome.tokenEstimate === undefined ? "" : `, ~${outcome.tokenEstimate} tokens`;
    // Which read answered, because the two are different claims and the log is where an operator
    // finds out which one this deployment is actually living on. A store whose every turn is
    // answered by the fallback is not recalling what it was asked about; it is ranking words.
    const via = outcome.via ? ` via ${outcome.via}` : "";
    logger?.info?.(
      `${PLUGIN_ID}: recalled ${outcome.count} record(s)${via}${outcome.degraded ? " (partial)" : ""}${cost}`,
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

/**
 * The digest's own line, said separately from recall's or not at all.
 *
 * Separate because it is a separate read with a separate reason to be absent, and an operator asking
 * "why is there no digest" is asking about the window read, not about the bundle. Nothing here warns:
 * a digest that did not happen leaves the turn exactly as it would have been without the feature, and
 * a warning would put an outage's noise level on an absence that costs nothing.
 */
function reportDigest(outcome, logger) {
  if (typeof outcome?.digest === "string" && outcome.digest) {
    logger?.info?.(
      `${PLUGIN_ID}: injected a session-opening digest of ${outcome.digestCount} record(s) ` +
        `over the last ${outcome.digestDays} day(s)`,
    );
    return;
  }
  if (outcome?.digestFailed) {
    logger?.info?.(
      `${PLUGIN_ID}: no session-opening digest, and recall is unaffected: ${outcome.digestFailed}`,
    );
    return;
  }
  if (outcome?.digestEmpty === true) {
    logger?.info?.(
      `${PLUGIN_ID}: no session-opening digest: nothing was recorded in the last ${outcome.digestDays} day(s)`,
    );
  }
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

    // The third, said the same way and for the same reason. Off is the right default — a digest is
    // tokens spent on something nobody asked for — so its absence is a note rather than a warning.
    if (positive(settings.digestDays, 0) <= 0) {
      api?.logger?.info?.(
        `${PLUGIN_ID}: no session-opening digest: set config.digestDays to the number of days of ` +
          `recent activity a session should wake up holding`,
      );
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
  once,
  searchBounds,
  composed,
  fallbackFor,
  searchArgv,
  digestArgv,
  digestBounds,
  digestPlan,
  renderDigest,
  digestLine,
  dayOf,
  claimOpening,
  sessionOf,
  withDigest,
  needleFrom,
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
  SEARCH_SHAPE,
  SEARCH_HEADING,
  MAX_SEARCH_TERMS,
  MIN_FALLBACK_MS,
  THREAD_MARKER,
  MAX_INFER_CHARS,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_MAX_RECORDS,
  DEFAULT_MAX_CHARS,
  HEADING,
  DIGEST_SHAPE,
  DIGEST_HEADING,
  DEFAULT_DIGEST_MAX_RECORDS,
  DEFAULT_DIGEST_MAX_CHARS,
  MIN_DIGEST_MS,
  SEEN_SESSIONS,
};
