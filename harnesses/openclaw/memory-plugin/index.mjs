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
// **And the third thing has to be told rather than read off the payload.** `ctx.agentId` is the
// host's name for this run — `main`, `pr`, `deploy` — and it is *not* the name the store filed the
// agent's records under, which is whatever caller the record socket signed as: `main_bot`, `pr_bot`,
// `deploy_bot`. The two are named separately on purpose, and the deployment's own setup says why —
// the socket is the evidence of who wrote, so a writer name belongs to the keyring rather than to
// this harness. Passing `ctx.agentId` straight through was the same hole as the actor alone, one
// layer down: a `--actor` naming nothing matched nothing on every turn, and the warning above was
// aimed one layer above where it happened. So `config.actors` is where a deployment states the map,
// and where it names nothing for an agent this asks no actor at all and says so. See `actorPlan`.
//
// **And the actor is background, which is a claim about how much of the page it may have.** A bundle
// fills its entities first and gives the actor whatever is left, so an actor that matches — which is
// what the map above finally made it do — takes the whole page on the turn that named no key, and
// hands the model the same rows whatever the question was. It is asked for separately now, bounded to
// a small allowance out of what the entities left, and not asked for at all where the entities found
// nothing. See `actorAllowance` for the number and `answerFor` for the two reads.
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

/**
 * Most of one page the actor's own activity may take, on a turn that had an answer to supplement.
 *
 * **The actor is a background source and this is the number that makes that true rather than said.**
 * A bundle composes out of entities and an actor, the service fills entities first and lets the actor
 * have the rest of the page, and for as long as the actor half matched nothing that was a rule with
 * no consequences. The moment it matched, it took whatever the keys left — which on a turn that named
 * no key at all is the whole page. Measured on the live deployment at 80 records: a greeting, a
 * generic prose question and a third generic question each came back with the same eight rows, byte
 * for byte, of the asking agent's last week, under the heading that says the records were composed
 * around this request.
 *
 * Three ways to size the share were available and this is the argument for the one taken:
 *
 *   - **A fraction of the page** tracks the page rather than the question. `maxRecords` is bought to
 *     hold more of the *answer*, so a deployment that raises it to sixteen because its entities have
 *     long histories would double its background at the same time, which is the wrong direction.
 *   - **A fixed number with no way to change it** decides for a deployment whose store this file has
 *     never seen — the same objection that keeps `digestDays` unset by default.
 *   - **A small fixed default an operator can move**, which is this. Two rows is enough to say what
 *     this agent did last and what it did before that; it is about eighty tokens against a page of
 *     around three hundred; and it cannot be mistaken for an answer at that size.
 *
 * The other half of the rule is not a number: the allowance is **zero on a turn whose entities
 * matched nothing**, because there is then no answer for background to be background *to*. That is
 * what keeps a page of the actor from arriving under a heading claiming it was composed around the
 * message, and it is what gives the ranked search and the session-opening digest their turns back.
 * See `actorAllowance`.
 */
const DEFAULT_ACTOR_MAX_RECORDS = 2;

/**
 * How little of the budget is still worth a background read.
 *
 * The same floor the fallback and the digest have, for the same reason: every read here shares one
 * deadline, and the one thing nobody asked for must not extend a wait somebody else is spending.
 */
const MIN_BACKGROUND_MS = 600;

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
 * Words that name a point on the calendar or the clock rather than a subject.
 *
 * Separate from the stoplist above, and dropped for a different reason. A framing word says nothing
 * about *this* question; a calendar word says nothing about *any* question. Every record carries a
 * timestamp and most prose about work carries a date, so a needle holding `2026` ranks on the store's
 * own clock. Measured on this deployment: `"2026"` alone matched 36 of 73 records, and the four terms
 * one host timestamp contributed matched the same 36. A term half a store contains is not a search —
 * it is a page of the store with a search's provenance on it.
 *
 * Names rather than shapes, because that is what the words of a date are; the shapes are below.
 */
const CALENDAR_WORDS = new Set([
  "mon", "monday", "tue", "tues", "tuesday", "wed", "weds", "wednesday", "thu", "thur", "thurs",
  "thursday", "fri", "friday", "sat", "saturday", "sun", "sunday",
  "jan", "january", "feb", "february", "mar", "march", "apr", "april", "may", "jun", "june",
  "jul", "july", "aug", "august", "sep", "sept", "september", "oct", "october", "nov", "november",
  "dec", "december",
  "gmt", "utc", "est", "edt", "cst", "cdt", "mst", "mdt", "pst", "pdt", "cet", "cest",
  "bst", "ist", "jst", "aest", "nzst",
]);

/**
 * A bare year, and an ISO date.
 *
 * Bounded to plausible years rather than any four digits: an order number, a port and an amount are
 * all four digits, and dropping those would be a different decision made by accident.
 */
const YEAR_SHAPED = /^(?:19|20|21)\d{2}$/;
const ISO_DATE_SHAPED = /^(?:19|20|21)\d{2}-\d{2}(?:-\d{2})?$/;

/** Whether one token names a moment rather than a subject. Read by the needle and by the envelope. */
function calendarToken(word) {
  const folded = String(word).toLowerCase();
  return CALENDAR_WORDS.has(folded) || YEAR_SHAPED.test(folded) || ISO_DATE_SHAPED.test(folded);
}

/**
 * How many leading lines may be read as the host's framing rather than the person's message.
 *
 * A bound rather than a judgement. One stamp is what this host prepends; a pasted log is a wall of
 * timestamps that is very much the message, and a stripper with no ceiling would eat it.
 */
const MAX_ENVELOPE_LINES = 4;

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
 *
 * And it is a limit on the read, not on the store: records have bodies, and every layer here returns
 * structure only, deliberately. Saying the store holds nothing more would be false, and it would stop
 * an agent even naming the record whose body it could go and ask for.
 */
const DIGEST_HEADING =
  "Recent activity in this deployment's memory, grouped by date. This is background, not an answer: " +
  "nobody asked for it and none of it is necessarily about this message. Record structure only — " +
  "who acted, when, and what they referenced. It does not say what any of it was about: records have " +
  "bodies, and by design no read here returns one.";

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
 * Whose activity a turn asks about: the writer name this agent's records were filed under.
 *
 * **An agent id is not a writer name, and nothing here may bridge the two by guessing.** The host
 * knows the agent this run is — `main`, `pr`, `deploy`. The store knows the caller each record was
 * signed by — `main_bot`, `pr_bot`, `deploy_bot`, `memory_import`. They are named separately and
 * deliberately: a record's writer is whatever its record socket signed as, so the writer name belongs
 * to the deployment's keyring. This plugin therefore cannot derive one from the other; it has to be
 * told, and `config.actors` is where a deployment says it.
 *
 * Three mechanisms were available. Two of them produce a name whatever the truth is, which is the
 * property that makes them worse than nothing here:
 *
 *   - **A suffix rule** — `${agentId}_bot` — is terse, and would have worked on the deployment this
 *     was written for. That is exactly what makes it dangerous: it promotes one deployment's naming
 *     convention to a fact about every deployment, and the first host that calls a writer anything
 *     else gets the silent zero back with a rule's confidence behind it. A convention and a fact are
 *     indistinguishable by their output when both return a string.
 *   - **The socket path** already in `config.read` looks like evidence and is not. The live
 *     deployment is its own counterexample: one read socket serves all three agents' recall, so a
 *     derivation would name that socket's writer as the actor for every turn whatever agent asked.
 *     Confidently wrong is worse than absent, because absent is legible.
 *
 * What is left is the verbose one: a map somebody wrote down, keyed by agent id. It invents nothing,
 * and its cost is real — one more thing to keep in step with the keyring. What makes that survivable
 * is that a stale map fails *by name* rather than in silence: see `unmapped`.
 *
 * Returns which of four things the actor of this turn is, so the caller can say which happened rather
 * than leave a reader to infer it from an empty page:
 *
 *   - `configured` — the read argv already names `--actor`. An operator's choice of *writer* is
 *     theirs, and the plan carries the name so the background read can be built from it; how much of
 *     the page that writer gets is this file's, and is bounded the same way for everyone.
 *   - `named` — the map names a usable writer for this agent. The only plan that adds a flag.
 *   - `unmapped` — this turn has an agent id and the config names no usable writer for it. **No
 *     `--actor` is passed.** Passing the agent id is what asked about a writer that never existed,
 *     and the empty set that comes back is indistinguishable from a quiet store; asking about the
 *     entities alone asks a narrower question honestly. A writer spelled as something that would be
 *     read as a flag takes this route too — it goes into an argument list, and the operator's fix is
 *     the same line of config either way.
 *   - `unnamed` — the turn carries no agent id at all, so there is nothing to look up.
 */
function actorPlan(argv, agentId, actors) {
  if (Array.isArray(argv) && argv.some(namesActor)) {
    return { kind: "configured", writer: actorWriterIn(argv) };
  }
  if (typeof agentId !== "string" || !agentId.trim()) return { kind: "unnamed" };
  const id = agentId.trim();
  const writer = actors && typeof actors === "object" ? actors[id] : undefined;
  if (typeof writer !== "string") return { kind: "unmapped", agentId: id };
  const trimmed = writer.trim();
  if (!trimmed || trimmed.startsWith("-")) return { kind: "unmapped", agentId: id };
  return { kind: "named", writer: trimmed };
}

/** Whether one argument is the actor flag, in either of the two spellings an argv may use. */
function namesActor(arg) {
  return arg === "--actor" || (typeof arg === "string" && arg.startsWith("--actor="));
}

/**
 * The writer an operator wrote into the reader argv, or nothing when what they wrote is not one.
 *
 * Read rather than merely detected, because the actor now has a read of its own: the flag has to be
 * taken *off* the read that answers the turn and put *on* the read that carries the background, and
 * both halves need the name. A `--actor` with no value after it, or one whose value would be read as
 * another flag, yields nothing — and `withoutActor` then leaves the argv alone, so the reader refuses
 * the malformed config exactly as it does today rather than having it quietly repaired here.
 */
function actorWriterIn(argv) {
  for (let at = 0; at < argv.length; at += 1) {
    const arg = argv[at];
    if (arg === "--actor") {
      const next = argv[at + 1];
      return typeof next === "string" && next.trim() && !next.startsWith("-") ? next.trim() : undefined;
    }
    if (typeof arg === "string" && arg.startsWith("--actor=")) {
      const value = arg.slice("--actor=".length).trim();
      return value && !value.startsWith("-") ? value : undefined;
    }
  }
  return undefined;
}

/**
 * The configured argv with the actor flag taken off it.
 *
 * What is left is the read that answers the turn: entities, and the keys inferred from the message.
 * The actor is asked separately and bounded separately, because a source that fills whatever the
 * others left is a source with no bound at all on the turn where the others found nothing.
 */
function withoutActor(argv) {
  const kept = [];
  for (let at = 0; at < argv.length; at += 1) {
    const arg = argv[at];
    if (arg === "--actor") {
      at += 1;
      continue;
    }
    if (typeof arg === "string" && arg.startsWith("--actor=")) continue;
    kept.push(arg);
  }
  return kept;
}

/**
 * The plan above as the argv the *background* read contributes.
 *
 * Nothing but a `named` plan adds a flag, and the reason a `configured` one does not is that its
 * argv already carries the operator's own — the background read is built from the configured argv
 * unchanged, and adding a second `--actor` would ask about two writers or be refused for asking
 * twice. Neither plan puts an actor on the read that answers the turn any more; see `answerFor`.
 */
function actorFor(argv, agentId, actors) {
  const plan = actorPlan(argv, agentId, actors);
  return plan.kind === "named" ? ["--actor", plan.writer] : [];
}

/**
 * How many rows of the page the actor may have on this turn, given what the entities took.
 *
 * Two rules, and the first is the one that matters. **Zero where the entities matched nothing.** The
 * actor is background to an answer, so a turn with no answer has nothing for it to be background to,
 * and a page of the asking agent's week is not made into a reply by arriving under a heading that
 * says a bundle composed it. That is also what hands the turn back to the two reads that exist for
 * exactly this case: the ranked search, whose heading concedes what it is, and the session-opening
 * digest, whose heading concedes more.
 *
 * Then a bound: at most `actorMaxRecords`, and never more than the page has left. So a turn naming
 * three entities whose histories fill the page gets no background at all — it did not need any — a
 * turn whose one entity answered thinly gets the full allowance, and a turn naming nothing gets none.
 * The middle case is the one the allowance is for, which is the right shape: a thin answer is worth
 * supplementing, a full one is not, and no answer must not be dressed as one.
 *
 * Zero is a legitimate setting and is therefore read as one — a deployment that wants no background
 * page at all sets `actorMaxRecords` to 0 rather than having it silently mean "use the default".
 */
function actorAllowance(settings, limits, shown) {
  if (!Number.isFinite(shown) || shown <= 0) return 0;
  const most = whole(settings?.actorMaxRecords, DEFAULT_ACTOR_MAX_RECORDS);
  return Math.max(0, Math.min(most, limits.maxRecords - shown));
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
 * Whether one line is host framing rather than something a person wrote.
 *
 * The test is what the line is *made of*, not what it looks like: split it into words, and if every
 * one of them is a calendar word, a shape a date has, or a run of digits — and at least one of them
 * actually names a moment — then the line said when and nothing else, which is a thing a host says
 * and not a thing a person asks.
 *
 * Deliberately not `Date.parse`. That would be the general reader for the general shape, and it
 * accepts `PROJ-2087` as a date in the year 2087 — so the one line the fallback exists to read would be
 * the line most likely to be thrown away. A classifier that is lenient in the direction of deleting
 * the message is the wrong kind of general.
 */
function envelopeLine(line) {
  // Letter/digit boundaries split too, so `2026-08-28T15:16:51Z` comes apart into its parts rather
  // than into `28T15` and `51Z`.
  const words = line.split(/[^A-Za-z0-9]+/).flatMap((part) =>
    part.split(/(?<=\d)(?=[A-Za-z])|(?<=[A-Za-z])(?=\d)/)).filter(Boolean);
  if (words.length === 0) return false;
  let named = false;
  for (const word of words) {
    if (calendarToken(word)) {
      named = true;
      continue;
    }
    // A run of digits is a day, an hour, a minute, a second or an offset; a lone letter is the `T`
    // or the `Z` a machine writes between them. Neither carries a subject, and neither on its own is
    // enough to call the line a timestamp — that is what `named` is for.
    if (/^\d+$/.test(word) || word.length === 1) continue;
    return false;
  }
  return named;
}

/**
 * The person's message, with the host's framing taken off the front.
 *
 * This is where the fallback's needle went wrong, and the mistake was one of provenance rather than
 * of parsing: `event.prompt` is not the message, it is the message with whatever the host chose to
 * prepend. On this host that is one RFC-1123 timestamp, and it turned every needle into a search for
 * the current date — but the class is wider than dates, because anything the host prepends arrives
 * the same way and is a subject nobody raised.
 *
 * Taken off here, at the one function that reads the payload, rather than in `needleFrom`: the
 * envelope is not the message for the *bundle's* inference either, and a reader told to infer lookup
 * keys from a date is being asked a question about the calendar just as surely.
 *
 * Only leading lines, only while something is left, and only a few of them. A prompt that is nothing
 * but a stamp keeps it — there is no message underneath to prefer, and `needleFrom` will decline it
 * on its own, which is the right answer arrived at by the honest route.
 */
function withoutEnvelope(prompt) {
  let rest = prompt;
  for (let stripped = 0; stripped < MAX_ENVELOPE_LINES; stripped += 1) {
    const at = rest.indexOf("\n");
    if (at < 0) break;
    const head = rest.slice(0, at).trim();
    const tail = rest.slice(at + 1).trim();
    if (!tail || !envelopeLine(head)) break;
    rest = tail;
  }
  return rest;
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
  // The envelope comes off before the cap, not after: it sits at the front, and the cap keeps the end.
  const message = withoutEnvelope(prompt);
  return {
    agentId: ctx?.agentId,
    entities: thread ? [`${kind}:${thread}`] : [],
    text: message ? message.slice(-MAX_INFER_CHARS) : undefined,
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
 * A whole-number setting whose zero means zero, or the default when the config says nothing usable.
 *
 * Separate from `positive` because the two kinds of setting differ in what a `0` is. A page of zero
 * records or a budget of zero milliseconds is a mistake, so `positive` reads those as "unset". An
 * allowance of zero is a deployment saying it wants no background page, which is a decision this file
 * must not overrule by handing back a default.
 */
function whole(value, fallback) {
  return Number.isInteger(value) && value >= 0 ? value : fallback;
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
 *
 * **The rows are two claims and the block says where one ends.** Everything the entities composed
 * comes first; whatever the actor's allowance carried is appended, and `answer.background` names how
 * many of the rows those are. Without that sentence the two are one undifferentiated list under a
 * heading that says all of it was gathered around this request, and only one half was. That the
 * background is bounded is why it is *worth* labelling rather than dropping — see `actorAllowance`.
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

  // Told apart by position rather than by inspecting the rows: the background is appended, so the
  // rows the entities answered with are the ones before it. A character ceiling cuts from the end,
  // which takes the background first — the cheaper thing to lose, and counted either way.
  const background = answer?.background;
  const answered = background ? records.length - background.shown : records.length;
  const answeredShown = Math.min(lines.length, answered);
  const carried = lines.length - answeredShown;

  const notes = [];
  const dropped = answered - answeredShown;
  if (dropped > 0) notes.push(`${dropped} further record(s) matched and are not shown.`);
  if (background && carried > 0) {
    // Stated as what it is rather than counted into the answer. This is `omitted`'s job done for a
    // source whose being cut is not a partial answer: there is always more of an agent's own
    // history, and saying so is honest where warning about it would be noise.
    const more = background.more === true || background.shown > carried;
    notes.push(
      `The last ${carried} row(s) are ${background.writer}'s own recent activity, carried as ` +
        `background rather than as an answer to this message` +
        `${more ? "; there is more of it than is shown" : ""}.`,
    );
  }
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
 * because it is the one axis this path can render without a body: the date is stamped, the actor is
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
 *
 * Calendar words are refused as terms even though `turnOf` has already taken the host's stamp off the
 * front. The two rules answer different questions and both are needed: the envelope is about *whose
 * words these are*, and this is about *what a word can distinguish*. A date a person typed themselves
 * is still a term every record in a dated store can match.
 */
function needleFrom(text) {
  if (typeof text !== "string") return undefined;
  const seen = new Set();
  const terms = [];
  for (const raw of text.split(/[^A-Za-z0-9_-]+/)) {
    if (terms.length >= MAX_SEARCH_TERMS) break;
    const word = raw.trim();
    if (word.length < MIN_TERM_CHARS) continue;
    if (calendarToken(word)) continue;
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
 * is written down here: **an entity hit takes the turn; a ranked search and a page of the actor do
 * not.**
 *
 * The rule used to read "a bundle takes the turn", and it was written when a bundle meant an answer.
 * It stopped meaning that the day the actor half began to match: the service fills entities first and
 * gives the actor the rest of the page, so a turn naming no key came back with a full bundle of the
 * asking agent's own week and the digest had no turn left to fire on. Measured on the live
 * deployment: with `config.actors` set, no digest was injected on any of four probe turns; with it
 * unset, the greeting produced one. The mechanism was intact the whole time.
 *
 * So the test is what *answered*, not what returned rows. A bundle whose entities matched is the
 * composed answer to the question actually asked, and nothing unasked-for goes in beside it. A bundle
 * that is nothing but the actor's page is not an answer — it is the same rows on every turn, and the
 * bounded version of it that `actorAllowance` allows is not even offered on a turn with no keys.
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
  if (why) return { kind: "unavailable", why, asked: named, actor: actorPlan(argv, turn?.agentId, settings?.actors) };

  // One deadline for however many reads happen, so the outer bound this hook registered still means
  // what it says.
  const deadline = Date.now() + budgetMs;

  const outcome = await answerFor(settings, argv, turn, named, limits, budgetMs, deadline);
  // The entities answered the question. Nothing unasked-for goes in beside it, and no second read is
  // spent finding out what one would have said. A ranked hit does not clear that bar, and neither
  // does the actor's own page, which is why it is never asked for alone — see above.
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
  // Which actor this turn asks about, or which of the three ways it asks about none. Carried on every
  // outcome below rather than recomputed by the log: "no actor was asked about" is a fact about the
  // read that happened, and a reader of the log must not have to re-derive it from the config.
  const actor = actorPlan(argv, turn?.agentId, settings?.actors);
  // **The actor is not on this read.** It used to be, and one flag on one read is why a bundle could
  // not tell a caller which of its two sources filled the page: the service fills entities first and
  // gives the actor the rest, so on a turn naming no key the actor got all of it, reported the excess
  // as an omission, and set `degraded` for ever. Asked separately, it is bounded separately — and the
  // question this read answers is the one the heading claims it answered.
  const base = actor.kind === "configured" && actor.writer ? withoutActor(argv) : argv;
  const args = [
    ...base.slice(1),
    ...entitiesFor(base, named),
    ...inferenceFor(base, settings?.specDir, turn?.text),
    ...bounds(base, budgetMs, limits.maxRecords),
  ];

  const first = await once(base[0], args, budgetMs);
  if (first.kind === "failed") return { kind: "unavailable", why: first.why, asked: named, actor };
  if (first.records.length > 0) {
    const page = await backgroundOf(settings, argv, turn, first.records.length, limits, deadline);
    const extra = { asked: named, via: READ_SHAPE, actor };
    if (page?.why) extra.backgroundFailed = page.why;
    return composed(withActorPage(first, page), limits, HEADING, extra);
  }

  // The bundle answered and matched nothing. Everything below is the second question, and it is a
  // different question: not "what is filed under these keys" but "what mentions these words".
  // Built from the read without the actor on it, for the same reason: a ranked search is a question
  // about the message's words, and an actor flag would narrow it to one writer's records without the
  // heading saying so — where the `search` read accepts the flag at all.
  const fallback = fallbackFor(settings, base, turn, deadline);
  if (!fallback) return { kind: "empty", asked: named, actor };

  const second = await once(base[0], fallback.args, fallback.budgetMs);
  // A failed fallback is still an empty bundle, not an outage: the precise read succeeded and found
  // nothing, which is an answer. Reporting it as unavailable would call a working store broken.
  if (second.kind === "failed") {
    return { kind: "empty", asked: named, actor, fallbackFailed: second.why };
  }
  if (second.records.length === 0) return { kind: "empty", asked: named, actor, searched: true };
  return composed(second, limits, SEARCH_HEADING, { asked: named, via: SEARCH_SHAPE, actor });
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

/**
 * The background read, or nothing when there is no actor, no room, or no time.
 *
 * The same reader and the same socket asked the same `bundle` shape, with the actor and nothing else:
 * no entity, no inference, and a `--limit` that is the allowance rather than the page. **Asking for
 * only the allowance is what makes overflowing the page impossible** rather than merely unlikely, and
 * the merge trims to it a second time so that an operator who pinned their own `--limit` in the argv
 * — which `bounds` leaves alone, because a bound in the config was chosen for a reason — cannot buy
 * the actor a bigger share of somebody else's page by accident.
 */
function backgroundPlan(settings, argv, turn, shown, limits, deadline) {
  const plan = actorPlan(argv, turn?.agentId, settings?.actors);
  const writer = plan.writer;
  if (typeof writer !== "string" || !writer) return undefined;
  const allowance = actorAllowance(settings, limits, shown);
  if (allowance <= 0) return undefined;
  const left = deadline - Date.now();
  if (left < MIN_BACKGROUND_MS) return undefined;
  return {
    writer,
    allowance,
    args: [
      ...argv.slice(1),
      ...actorFor(argv, turn?.agentId, settings?.actors),
      ...bounds(argv, left, allowance),
    ],
    budgetMs: left,
  };
}

/**
 * The actor's page, read and bounded, or nothing when it declined — or `{writer, why}` when it failed.
 *
 * **A background read that fails costs the turn nothing**, exactly as a digest that fails does. The
 * answer this supplements has already been composed; reporting a failure to fetch a supplement as a
 * partial answer would put the words "not safe to act on" on a bundle that is complete.
 */
async function backgroundOf(settings, argv, turn, shown, limits, deadline) {
  const plan = backgroundPlan(settings, argv, turn, shown, limits, deadline);
  if (!plan) return undefined;
  const answer = await once(argv[0], plan.args, plan.budgetMs);
  if (answer.kind === "failed") return { writer: plan.writer, why: answer.why };
  const records = answer.records.slice(0, plan.allowance);
  return {
    writer: plan.writer,
    records,
    // **This is the flag that must not become the answer's.** `degraded` here says the actor has more
    // history than its allowance, which is the normal state of any agent that has been running, and
    // it is reported as a sentence about the background rather than as a warning about the bundle.
    // See `withActorPage`, where it is deliberately not carried across.
    more: answer.degraded === true || answer.records.length > records.length,
    token_estimate: answer.token_estimate,
  };
}

/**
 * The answer with the actor's page appended, and the actor's own bounds left where they belong.
 *
 * Three things are carried across and one is not:
 *
 *   - **the rows**, minus anything the answer already had. One record can be both an entity's history
 *     and the actor's, and a page that showed it twice would spend the allowance saying nothing.
 *   - **how many rows they are**, so the block can say where the answer stops. See `renderContext`.
 *   - **whether there is more of them**, which is `omitted`'s job for this source.
 *   - **not `degraded`.** The answer's partiality is the answer's read's to report. An actor with
 *     more history than its allowance is not a partial answer, it is an agent that has been working,
 *     and a sentence that fires on every turn stops being read on the turn it matters.
 */
function withActorPage(answer, page) {
  const records = Array.isArray(page?.records) ? page.records : [];
  if (records.length === 0) return answer;
  const seen = new Set(answer.records.map((record) => record?.record_id).filter(Boolean));
  const added = records.filter((record) => !record?.record_id || !seen.has(record.record_id));
  if (added.length === 0) return answer;
  const tokens = Number.isFinite(answer.token_estimate) && Number.isFinite(page.token_estimate)
    ? answer.token_estimate + page.token_estimate
    : answer.token_estimate;
  return {
    ...answer,
    records: [...answer.records, ...added],
    token_estimate: tokens,
    background: { writer: page.writer, shown: added.length, more: page.more === true },
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
    // The answer's own read decides this, and the actor's page is not part of it. See `withActorPage`.
    degraded: answer.degraded === true,
    tokenEstimate: Number.isFinite(answer.token_estimate) ? answer.token_estimate : undefined,
    background: answer.background,
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
  reportBackground(outcome, logger);
  reportActor(outcome, logger);
  if (outcome?.kind === "recalled") {
    const cost = outcome.tokenEstimate === undefined ? "" : `, ~${outcome.tokenEstimate} tokens`;
    // Which read answered, because the two are different claims and the log is where an operator
    // finds out which one this deployment is actually living on. A store whose every turn is
    // answered by the fallback is not recalling what it was asked about; it is ranking words.
    const via = outcome.via ? ` via ${outcome.via}` : "";
    // And how much of it was the actor's own activity rather than the answer. A bundle used to ask
    // "what has this writer been doing" alongside the keys and let it have whatever the keys left, so
    // on a store one agent wrote most of, a whole page of that agent's week arrived in front of every
    // reply. It is now a bounded tail, and this clause is where an operator sees how long it is.
    const background = outcome.background;
    const whose = background
      ? `, plus ${background.shown} background row(s) from actor ${background.writer}`
      : "";
    logger?.info?.(
      `${PLUGIN_ID}: recalled ${outcome.count} record(s)${via}${whose}${outcome.degraded ? " (partial)" : ""}${cost}`,
    );
    return;
  }
  if (outcome?.kind === "empty") {
    // Named, because the first question about an empty answer is what was asked. A turn that could
    // name no entity at all reads as `about nothing in particular`, and that is a different problem
    // from a store with nothing in it — the fix for one is the wiring, for the other is time.
    const about = outcome.asked?.length ? outcome.asked.join(", ") : "nothing in particular";
    // The actor is not named here, and its absence from this line is the point: a turn whose keys
    // matched nothing does not ask about the actor at all, because a page of the asking agent's own
    // week is background to an answer and there is no answer here for it to be background to.
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
 * The actor's own line, said when this turn asked about none because the config named none.
 *
 * The whole point of the mechanism above is that this case is *loud*. A `--actor` naming a writer
 * nothing was ever written under returns an empty page, and an empty page is exactly what a quiet
 * store returns — so the defect had no symptom at all, and every recall line in the log read `via
 * search` while nobody could see why. Not passing the flag is the honest question; this line is what
 * makes the difference visible without reading the config.
 *
 * At info and every turn it happens, not once at load: an agent id the map has never heard of is
 * per-turn news — a new agent, a renamed writer, a map that drifted from the keyring — and load time
 * cannot know which agents will actually arrive. Nothing warns, because the turn proceeds exactly as
 * a turn with no actor to ask about always did.
 */
function reportActor(outcome, logger) {
  const plan = outcome?.actor;
  if (plan?.kind !== "unmapped") return;
  logger?.info?.(
    `${PLUGIN_ID}: no actor was asked about: config.actors names no writer for agent ` +
      `"${plan.agentId}", so this turn asked only about what it could name. An agent id is not a ` +
      `writer name — a record carries the caller its socket signed as, and only this deployment's ` +
      `keyring knows which that is`,
  );
}

/**
 * The background read's own line, said only when it failed.
 *
 * Said at info and never as a warning, for the same reason the digest's failure is: the turn carries
 * the answer it composed, and a supplement that could not be fetched changes nothing a reader of that
 * answer would do. A success needs no line of its own — the recall line names the rows.
 */
function reportBackground(outcome, logger) {
  if (!outcome?.backgroundFailed) return;
  logger?.info?.(
    `${PLUGIN_ID}: no background page for the actor, and the answer is unaffected: ${outcome.backgroundFailed}`,
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

    // The third half, and the one whose absence used to be invisible. The other two are settings a
    // deployment may reasonably not want; this one is the difference between an actor lookup and no
    // actor lookup at all, and until it existed the plugin sent an agent id that matched nothing and
    // reported the result as a quiet store. Said either way — what is mapped, or that nothing is —
    // because a map that has drifted from the keyring looks exactly like a map that is right.
    const actors = settings.actors && typeof settings.actors === "object" ? settings.actors : {};
    const mapped = Object.entries(actors).filter(([, writer]) => typeof writer === "string" && writer.trim());
    if (mapped.length === 0) {
      api?.logger?.info?.(
        `${PLUGIN_ID}: no actor is looked up: set config.actors to this deployment's map from agent ` +
          `id to the writer name its records carry, for example {"main": "main_bot"}. The names are ` +
          `the keyring's and this plugin cannot derive one from the other, so an agent it does not ` +
          `name asks about no actor rather than about a writer that may not exist`,
      );
    } else {
      // The allowance is said beside the map, because the map alone reads as "the actor half is on"
      // and the number is what decides whether that means a supplement or a page. Zero is a
      // deployment saying it wants no background at all, and it is said as such rather than omitted.
      const allowance = whole(settings.actorMaxRecords, DEFAULT_ACTOR_MAX_RECORDS);
      api?.logger?.info?.(
        `${PLUGIN_ID}: actors: ${mapped.map(([id, writer]) => `${id} records as ${writer.trim()}`).join(", ")}` +
          `; each may carry ${allowance} background row(s) of its own activity behind an answer, ` +
          `and none on a turn whose entities matched nothing`,
      );
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
  actorAllowance,
  actorWriterIn,
  withoutActor,
  backgroundPlan,
  backgroundOf,
  withActorPage,
  reportBackground,
  whole,
  DEFAULT_ACTOR_MAX_RECORDS,
  MIN_BACKGROUND_MS,
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
  actorPlan,
  reportActor,
  entitiesFor,
  inferenceFor,
  threadOf,
  turnOf,
  withoutEnvelope,
  envelopeLine,
  calendarToken,
  MAX_ENVELOPE_LINES,
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
