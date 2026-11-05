// Phase 2a (card feea07eb, route A; PLAN.md phase 2a): the hourly second line behind the recorder.
// The recorder Worker (src/recorder/) is the only intended writer of the observatory-records
// bucket: it refuses bad records before storing them and names each one with a gap-free sequence
// number. This job re-reads every record the recorder stored since its last run, in that order,
// against the same contract (src/contract.ts), and alerts on anything the recorder should have
// refused or that something else wrote. It only tells; it never acts on the front desk.
// Once PIN is set (card 6a04908f), a record from PIN.from on is the one copy at its number that
// the recorder signed; any other object there is foreign, and the bookmark never passes a number
// without exactly one signed copy.
// Card af0e4a2f: the healthchecks light means only "the checker ran and read what it should".
// Every problem is an incident with a stable id, alerted once and listed until no longer found;
// nobody can mark one seen. Threat table: studio-os docs/specifications/trust-but-verify/
// RECORDS-LIGHT-THREATS-af0e4a2f.md.
import { alert, redact, type AlertEnv } from "./alert.ts";
import { DAY_CAP, GRANT_TTL_MS, MAX_STORED_BYTES, ROOT, sealed, sha256, SKEW_MS, unb64, validate, type Envelope, type Stage } from "./contract.ts";
import { isOpStage, nameOf, OPS_FROM, poolUse, validateOp, type AnyStage, type Op, type OpResult } from "./ops.ts";
import { badOp, capacityFindings, countBytes, fp, loadOps, measures, onApproval, onOp, onRequest, onResult, poolFindings, pruneDays, settle, type OpsState } from "./runcheck.ts";
import { readLockLength, type LockEnv } from "./lock.ts";

export interface RecordsEnv extends AlertEnv, LockEnv {
  RECORDS?: Pick<R2Bucket, "list" | "get">; // read and list only: this job never writes there
  COPY: Pick<R2Bucket, "get" | "put">; // state/records.json lives in the copy bucket's unlocked state/
  PING_URL_RECORDS?: string; // this job's own healthchecks check; Ben creates it at the end of the build
}

/** The recorder's public key (base64, as GET /v1/status shows it) and the first record number it must have signed. */
export interface Pin { key: string; from: number }
// Set only by a Ben-merged PR, from the recorder's status. Undefined: nothing is expected signed yet.
// Pinned 2026-11-02 from GET /v1/status after PR #16 deployed (seq 0, so every record is signed).
export const PIN: Pin | undefined = { key: "AeN3/Dl3QicxXBObHVyLdhMmWGoDpjVO44LoB0sRV+s=", from: 1 };

export const RECORDS_BUCKET = "observatory-records"; // the RECORDS binding's bucket (wrangler.jsonc)
export const LOCKED = "records/";
export const MIN_LOCK_SECONDS = 400 * 86_400; // over a year of history, then lifecycle may delete
export const STATE_KEY = "state/records.json";
export const PAGE = 500; // records read an hour (one list and one read each): more than the recorder can take in a day
export const SWEEP_HOUR = 4; // UTC: once a day every name in the bucket is counted
export const SWEEP_PAGES = 200; // up to 200,000 records counted; beyond that the sweep says so
export const MAX_OPEN = 2_000; // grants remembered for the order check
export const MAX_SWEPT = 50;
export const MAX_NAMES_AT = 1_000; // names listed under one record number before the hour gives up as unverified
export const MAX_COPIES = 20; // objects read at one record number before the hour gives up as unverified
export const MAX_INCIDENTS = 200; // open incidents kept, worst first
export const MAX_DROPPED = 5_000; // ids of incidents with no room, kept so the overflow line knows what is new
export const MAX_SWEEP_READS = 20; // record numbers with extra names the daily count reads
export const TAIL_PAGES = 5; // pages of names after the bookmark listed to prove nothing higher exists (X2)
export const REMIND_DAY = 1, REMIND_HOUR = 14; // UTC Monday 14:00 (8 am Central): the weekly list of what is open

/** One finding: `id` is stable across hours so Ben hears about it once. Text never holds writer-chosen words. */
export interface Finding { id: string; text: string }
/** A finding kept on the standing list: `since` is the UTC day it was first found; `told` once a channel took its alert. */
export interface Incident extends Finding { since: string; told: boolean }
interface Open { job: string; req: string; at: number; stages: Stage[] }
// `sealed`: numbers from the pin's start up to `to` were confirmed signed under the pin with this key.
// `held`/`snap` come only from the checker before signing; they are read once, never saved again.
// `alerted`/`queued` come only from the checker before af0e4a2f: read once to carry what was told.
interface State { sealed?: { key: string; to: number }; held?: unknown[]; snap?: { seq: number; open: Record<string, Open>; days: Record<string, number> }; seq?: number; open?: Record<string, Open>; days?: Record<string, number>; swept?: Finding[]; incidents?: Incident[]; dropped?: string[]; droppedFull?: boolean; unverifiedTold?: boolean; reminded?: string; alerted?: string[]; queued?: Finding[]; ops?: OpsState }

const day = (d: Date) => d.toISOString().slice(0, 10);
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
/** A short fingerprint for a name we must not repeat: enough for Ben (or an agent) to find it. */
const tag = async (name: string) => (await sha256(name)).slice(0, 12);
// A name under records/v1/ outside the record format: locked like a record, so it stays listed.
const junk = async (name: string): Promise<Finding> => { const t = await tag(name); return { id: `junk:${t}`, text: `something outside the record format, fingerprint ${t}` }; };
const pad = (n: number) => String(n).padStart(12, "0");
// How a grant id appears in alerts (runcheck.ts fp): a fingerprint, never the id. Grant findings also name the record number.
export { fp };
// Worst first: what ran unrecorded or unchecked before what is merely malformed.
const RANK = ["forged", "missing", "unsigned", "unreadable", "unrecorded", "unapproved", "op-uncovered", "op-unlinked", "op-incomplete", "op-late", "op-unsettled", "approval-first", "mismatch", "duplicate", "duplicate-number", "foreign", "gap", "lock", "runway", "capacity", "cap", "pool", "backlog", "verdict-first", "bad", "sweep", "junk", "stray"];
const LOW = RANK.indexOf("junk"); // junk and stray: cheap for a writer to make by the thousand
const kind = (id: string) => id.split(":")[0];
const rank = (f: Finding) => { const i = RANK.indexOf(kind(f.id)); return i < 0 ? RANK.length : i; };
// Kinds a full run computes afresh (`sweep`: carried hourly from the last daily count): they leave
// the list when a full run no longer finds them. Every other kind is about a record read once and
// locked for 400 days, so it stays listed.
const RECHECKED = new Set(["lock", "stray", "gap", "cap", "backlog", "sweep", "unreadable", "pool", "capacity", "runway"]);
const isFinding = <T>(f: T): f is T & Finding => typeof (f as Finding)?.id === "string" && typeof (f as Finding)?.text === "string";

/** Checks one stored record on its own: its envelope against its name and R2's upload time, then the writer's body. */
export async function checkStored(seq: number, grant: string, stage: AnyStage, uploaded: Date, stored: string): Promise<{ finding?: Finding; env?: Envelope; job?: string; request?: string; record?: Record<string, unknown> }> {
  const shown = await fp(grant);
  const bad = (why: string) => ({ finding: { id: `bad:${seq}`, text: `record ${seq} (${shown}/${stage}): ${why}` } });
  let e: Envelope;
        try {
      e = JSON.parse(stored);
        } catch {
    return bad("not JSON");
  }
  if (!e || (e.v !== 1 && e.v !== 2) || e.seq !== seq || e.grant !== grant || (e.stage as AnyStage) !== stage) return bad("its envelope does not match its name");
  if (typeof e.recorded_at !== "string" || !ISO.test(e.recorded_at) || Math.abs(Date.parse(e.recorded_at) - uploaded.getTime()) > SKEW_MS) return bad("its recorded time is missing or far from when it was stored");
  if (typeof e.body !== "string" || e.sha256 !== (await sha256(e.body))) return bad("its body does not match its hash");
  // Op records have their own format (ops.ts); everything else is the grant contract, unchanged.
  const v = isOpStage(stage) ? validateOp(e.body) : validate(e.body);
  if (!v.ok) return bad(v.why);
  if (v.record.grant !== grant || v.record.stage !== stage) return bad("its body names a different grant or stage than its name");
  const r = v.record as unknown as Record<string, unknown>;
  return { env: e, job: v.record.job, request: typeof r.request === "string" ? r.request : undefined, record: r };
}

/** True if `text` is an envelope the recorder signed for exactly this object name and number. */
export async function signedBy(key: CryptoKey, n: number, name: string, text: string): Promise<boolean> {
  const m = nameOf(name);
  try {
    const e = JSON.parse(text) as Envelope;
    if (!m || m.n !== n || !e || e.v !== 2 || e.seq !== n || e.grant !== m.grant || (e.stage as AnyStage) !== m.stage || e.tag !== m.tag || typeof e.sig !== "string") return false;
    return await crypto.subtle.verify("Ed25519", key, unb64(e.sig), sealed(e));
  } catch {
    return false;
  }
}

/** The copies at one number sorted by the pinned key: signed for that number, foreign, or unreadable. */
async function sealsAt(bucket: Pick<R2Bucket, "get">, key: CryptoKey, n: number, cands: R2Object[]) {
  const seals: { o: R2Object; body: string }[] = [], foreign: Finding[] = [];
  let unreadable = false;
  for (const c of cands) {
    const text = c.size > MAX_STORED_BYTES ? null : await bucket.get(c.key).then((b) => (b ? b.text() : undefined), () => undefined);
    if (text === undefined) unreadable = true;
    else if (text !== null && (await signedBy(key, n, c.key, text))) seals.push({ o: c, body: text });
    else {
      // The exact object: its name and its bytes (or size, when too big to read).
      const t = await tag(c.key), b = text === null ? `big${c.size}` : (await sha256(text)).slice(0, 12);
      foreign.push({ id: `foreign:${n}:${t}:${b}`, text: `record ${n}: an object the recorder did not sign, fingerprint ${t}: something wrote around the recorder` });
    }
  }
  return { seals, foreign, unreadable };
}
// A number the run could not read: the light goes red, and each such number is its own incident.
const stuck = (n: number, text: string): Finding => ({ id: `unreadable:${n}`, text });
// Ids written before af0e4a2f that name no exact object: the old daily count (`foreign:<count>`)
// and the old foreign id without a content fingerprint. Dropped at load; the daily count re-finds plants.
const OLD_FOREIGN = /^foreign:\d+(:[0-9a-f]{12})?$/;
// The record number a daily-count problem is about (`sweep:unreadable:<n>`, `sweep:crowded:<n>`).
const numberOf = (id: string) => Number(/^sweep:(?:unreadable|crowded):(\d+)$/.exec(id)?.[1] ?? NaN);
const forged = (n: number, count: number): Finding => ({ id: `forged:${n}`, text: `${count} objects at record number ${n} carry the recorder's signature: its key may be stolen` });

/** The order check for one record, against the grants seen so far. Updates `open`. */
export function checkOrder(open: Record<string, Open>, grant: string, stage: Stage, job: string, request: string | undefined, sha: string, at: number, n: number, shown: string): Finding | undefined {
  const g = Object.hasOwn(open, grant) ? open[grant] : undefined;
  if (stage === "request") {
    if (g) return { id: `duplicate:${grant}:request`, text: `grant ${shown} (record ${n}) has a second request record` };
    open[grant] = { job, req: sha, at, stages: ["request"] };
    return undefined;
  }
  if (!g) {
    if (stage === "result") return { id: `unrecorded:${grant}`, text: `grant ${shown} (record ${n}) has a result with no request record before it: something ran unrecorded` };
    return { id: `${stage === "approval" ? "approval-first" : "verdict-first"}:${grant}`, text: `grant ${shown} (record ${n}) has a${stage === "approval" ? "n approval" : " verdict"} with no request record before it` };
  }
  if (g.stages.includes(stage)) return { id: `duplicate:${grant}:${stage}`, text: `grant ${shown} (record ${n}) has a second ${stage} record` };
  // A stage counts as present only once it names its own request and job (card 1a272a5c V7.4): a
  // mismatched approval never makes a later result look approved, nor a run look approved.
  if (request !== g.req || job !== g.job) return { id: `mismatch:${grant}`, text: `grant ${shown} (record ${n}): a later record names a different request or job than its request record` };
  g.stages.push(stage);
  if (stage === "result" && !g.stages.includes("approval")) return { id: `unapproved:${grant}`, text: `grant ${shown} (record ${n}) has a result with no approval record before it` };
  return undefined;
}

/** Every name under one record number's prefix, paged, up to MAX_NAMES_AT: record names and anything else. */
async function namesAt(bucket: Pick<R2Bucket, "list">, prefix: string): Promise<{ cands: R2Object[]; junk: string[]; capped: boolean }> {
  const cands: R2Object[] = [], junk: string[] = [];
  let cursor: string | undefined, seen = 0;
  do {
    const page = await bucket.list({ prefix, cursor, limit: 1000 });
    for (const o of page.objects) (nameOf(o.key) ? cands.push(o) : junk.push(o.key));
    seen += page.objects.length;
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor && seen < MAX_NAMES_AT);
  return { cands, junk: junk.slice(0, 20), capped: Boolean(cursor) };
}

/** Names outside records/v1/: the bucket's top level and records/ itself, one bounded page each. */
async function strays(bucket: Pick<R2Bucket, "list">): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const [prefix, allowed] of [["", "records/"], ["records/", ROOT]] as const) {
    const page = await bucket.list({ prefix, delimiter: "/", limit: 1000 });
    for (const name of [...page.delimitedPrefixes.filter((p) => p !== allowed), ...page.objects.map((o) => o.key)]) {
      const t = await tag(name);
      out.push({ id: `stray:${t}`, text: `something outside the record format, fingerprint ${t}` });
    }
    if (page.truncated) out.push({ id: `stray:more:${prefix}`, text: "more than a page of names outside the record format" });
  }
  return out;
}

/**
 * Once a day, every name under records/v1/ up to the bookmark: each number must hold exactly one
 * record. Numbers holding more than one name are read (up to MAX_SWEEP_READS) and their extra
 * objects named exactly as the hourly read names them, so a plant keeps one id however many
 * records follow it (the bucket lister supplies every name; the writer supplies nothing compared).
 * `incomplete` says why the count did not read everything it should (the run is then unverified).
 * `cleared`: numbers it read today and found readable and not crowded, counted before any cap.
 */
async function sweep(bucket: Pick<R2Bucket, "list" | "get">, key: CryptoKey | undefined, from: number, seq: number, now: Date): Promise<{ found: Finding[]; incomplete?: string; cleared: Set<number>; bytes: number }> {
  const out: Finding[] = [], junked: Finding[] = [], shared: { n: number; cands: R2Object[] }[] = [];
  let cursor: string | undefined, last = 0, here: R2Object[] = [], over = 0, incomplete: string | undefined, bytes = 0;
  // Junk is kept apart (bounded) so a flood of junk names can never crowd out a plant or a gap.
  const add = (f: Finding) => out.push(f);
  const close = () => { if (here.length > 1) shared.push({ n: last, cands: here }); };
  const lost = (to: number) => { for (let n = last + 1; n < to; n++) if (out.length < MAX_SWEPT) add({ id: `missing:${n}`, text: `record ${n} is gone from the bucket: something deleted or renamed it` }); else over++; };
  for (let pages = 0; ; pages++) {
    if (pages === SWEEP_PAGES) {
      add({ id: "sweep:incomplete", text: (incomplete = `over ${SWEEP_PAGES * 1000} records: the daily count could not finish`) });
      break;
    }
    const page = await bucket.list({ prefix: ROOT, cursor, limit: 1000 });
    for (const o of page.objects) {
      const m = nameOf(o.key);
      if (!m) { if (junked.length < MAX_SWEPT) junked.push(await junk(o.key)); else over++; continue; }
      const n = m.n;
      if (n > seq) continue; // not read yet: the hourly read reaches it
      bytes += o.size; // every object at a read number, the recorder's or not: what the bucket holds
      if (n !== last) { close(); lost(n); last = n; here = []; }
      here.push(o);
    }
    cursor = page.truncated ? page.cursor : undefined;
    if (!cursor) break;
  }
  close();
  if (!cursor) lost(seq + 1); // an unfinished count cannot tell missing from not yet listed
  // A different window of crowded numbers each day, so a plant past the first few is still read.
  const start = shared.length > MAX_SWEEP_READS ? (Math.floor(now.getTime() / 86_400_000) * MAX_SWEEP_READS) % shared.length : 0;
  const window = [...shared, ...shared].slice(start, start + Math.min(MAX_SWEEP_READS, shared.length));
  for (const { n, cands } of window) {
    if (cands.length > MAX_COPIES) add({ id: `sweep:crowded:${n}`, text: (incomplete = `${cands.length} objects share record number ${n}: the daily count could not read them`) });
    else if (key && n >= from) {
      const s = await sealsAt(bucket, key, n, cands);
      s.foreign.forEach(add);
      if (s.seals.length > 1) add(forged(n, s.seals.length));
      if (s.unreadable) add({ id: `sweep:unreadable:${n}`, text: (incomplete = `record ${n}: an object there could not be read by the daily count`) });
    } else add({ id: `duplicate-number:${n}`, text: `${cands.length} objects share record number ${n}, found by the daily count: something wrote around the recorder` });
  }
  // Counts are part of these ids: when the hidden amount changes, Ben hears again.
  if (shared.length > MAX_SWEEP_READS) add({ id: `sweep:more:${shared.length}`, text: `${shared.length - MAX_SWEEP_READS} more record numbers hold extra objects: the daily count read only ${MAX_SWEEP_READS}` });
  const all = [...out, ...junked].sort((x, y) => rank(x) - rank(y)), kept = all.slice(0, MAX_SWEPT);
  over += all.length - kept.length;
  if (over) kept.push({ id: `sweep:over:${over}`, text: `${over} more findings from the daily count could not be kept: read the records` });
  const stuckAt = new Set(out.map((f) => numberOf(f.id)));
  return { found: kept, incomplete, cleared: new Set(window.map((w) => w.n).filter((n) => !stuckAt.has(n))), bytes };
}

export type RecordsVerdict = "ran" | "unverified";

/** One hour's run: read what is new, judge, alert once per new finding that is delivered, keep state, ping. `pin` null: no pin. */
/** `opsFrom`: ops.ts OPS_FROM, a reviewed constant (never an env var); tests pass their own, as with `pin`; null: unset. */
export async function runRecords(env: RecordsEnv, fetchFn: (req: Request) => Promise<Response>, now: Date, pin: Pin | null = PIN ?? null, opsFrom: number | null = OPS_FROM ?? null) {
  let prev: State = {};
  try {
    const saved = await env.COPY.get(STATE_KEY);
    if (saved) prev = JSON.parse(await saved.text());
  } catch { /* an unreadable state re-reads from the start and re-alerts at worst: safer than silence */ }
  // No prototype: a grant id can never reach a built-in object property.
  const bare = <T>(o: unknown): Record<string, T> => Object.assign(Object.create(null), o && typeof o === "object" ? o : {});
  let open = bare<Open>(prev.open);
  let days = bare<number>(prev.days);
  let seq = Number.isInteger(prev.seq) ? prev.seq! : 0; // the last record number checked: the bookmark
  if (Array.isArray(prev.held) && prev.held.length) {
    // The checker before signing passed these numbers without counting them: read again from just
    // before the first, with the bookkeeping it saved there, so none is skipped (Codex r1 #1).
    const n = prev.held.filter((x): x is number => Number.isInteger(x));
    if (prev.snap && Number.isInteger(prev.snap.seq)) ({ seq } = prev.snap), (open = bare<Open>(prev.snap.open)), (days = bare<number>(prev.snap.days));
    else if (n.length) seq = Math.min(seq, Math.min(...n) - 1);
  }
  const ops = loadOps(prev.ops); // run ops (card 1a272a5c): defaults empty for a state from before
  let ended = false, tailClear = false; // the read reached an empty next number; nothing higher is listed
  let swept = Array.isArray(prev.swept) ? prev.swept.filter(isFinding).filter((f) => !OLD_FOREIGN.test(f.id)).slice(0, MAX_SWEPT + 1) : [];
  const findings: Finding[] = [];
  let cleared = new Set<number>(); // set only on the daily count's hour
  let verdict: RecordsVerdict = "ran", reason = "", checked = 0;

  let key: CryptoKey | undefined, from = Infinity;
  try {
    if (pin) {
      if (!Number.isInteger(pin.from) || pin.from < 1) throw new Error("bad from");
      key = await crypto.subtle.importKey("raw", unb64(pin.key), "Ed25519", false, ["verify"]);
      from = pin.from;
    }
  } catch {
    verdict = "unverified";
    reason = "the pinned recorder key could not be read";
  }
  // Numbers from the pin's start that were read before this pin took effect: each is checked once
  // for exactly one signed copy, without counting it again (Codex r1 #2).
  let sealedTo = key && prev.sealed?.key === pin!.key && Number.isInteger(prev.sealed.to) ? prev.sealed.to : from - 1;
  let sealDone = !key;
  try {
    if (key && env.RECORDS && verdict === "ran") {
      while (sealedTo < seq && checked < PAGE) {
        const n = sealedTo + 1, here = await namesAt(env.RECORDS, `${ROOT}${pad(n)}.`);
        for (const k of here.junk) findings.push(await junk(k));
        if (here.capped || here.cands.length > MAX_COPIES) {
          findings.push(stuck(n, `record ${n}: too many objects there to read`));
          throw new Error("too many");
        }
        const s = await sealsAt(env.RECORDS, key, n, here.cands);
        if (s.unreadable) {
          findings.push(stuck(n, `record ${n} could not be read`));
          throw new Error("unreadable");
        }
        findings.push(...s.foreign);
        if (s.seals.length > 1) {
          findings.push(forged(n, s.seals.length));
          throw new Error("forged"); // stays at n, like the main read
        } else if (!s.seals.length) findings.push({ id: `unsigned:${n}`, text: `record ${n} was read before the key was pinned and has no copy the recorder signed` });
        sealedTo = n;
        checked++;
      }
      if (sealedTo < seq) throw new Error("not done");
    }
    sealDone = true;
  } catch {
    verdict = "unverified";
    reason = `records read before the key was pinned are still being checked for signatures (up to ${sealedTo})`;
  }
  if (!env.RECORDS) {
    verdict = "unverified";
    reason = "no RECORDS binding";
  } else if (verdict === "ran") {
    try {
      // Each step asks for the next expected number by name, so names elsewhere in the bucket
      // (strays, planted high numbers) cost nothing and can never hide the records still to come.
      while (checked < PAGE) {
        const next = seq + 1, at = `${ROOT}${pad(next)}.`;
        const here = await namesAt(env.RECORDS, at);
        for (const k of here.junk) findings.push(await junk(k));
        if (here.capped) {
          verdict = "unverified";
          findings.push(stuck(next, (reason = `over ${MAX_NAMES_AT} names at record number ${next}: it could not be read`)));
          break;
        }
        const cands = here.cands;
        if (!cands.length) {
          // Nothing at the next number: the recorder has not written it yet. Anything right after
          // it is either a gap (a higher number without this one) or something outside the format.
          const after = (await env.RECORDS.list({ prefix: ROOT, startAfter: at, limit: 1 })).objects[0];
          const am = after && nameOf(after.key);
          if (after && !am) findings.push(await junk(after.key));
          else if (am) findings.push({ id: `gap:${am.n}`, text: `record numbers jumped from ${seq} to ${am.n}: number ${next} is missing` });
          ended = true;
          // The watermark's proof (X2): every name after the bookmark, paged to the end, holds no higher number.
          let cursor: string | undefined, pages = 0, higher = false;
          do {
            const page = await env.RECORDS.list({ prefix: ROOT, startAfter: at, cursor, limit: 1000 });
            higher ||= page.objects.some((x) => (nameOf(x.key)?.n ?? 0) > seq);
            cursor = page.truncated ? page.cursor : undefined;
          } while (cursor && !higher && ++pages < TAIL_PAGES);
          tailClear = !higher && !cursor;
          break;
        }
        if (cands.length > MAX_COPIES) {
          verdict = "unverified";
          findings.push(stuck(next, (reason = `${cands.length} objects share record number ${next}, over ${MAX_COPIES}: it could not be read`)));
          break;
        }
        let o = cands[0], body: string | null | undefined; // undefined: not read yet; null: not checked
        if (next >= from) {
          // The record is the one copy the recorder signed; anything else here was written around
          // it. No signed copy yet: the bookmark waits at this number and reads it again next hour.
          const { seals, foreign, unreadable } = await sealsAt(env.RECORDS, key!, next, cands);
          findings.push(...foreign);
          if (seals.length > 1) {
            findings.push(forged(next, seals.length));
            verdict = "unverified";
            reason = `record ${next} has ${seals.length} signed copies: reading stopped there`;
            break;
          }
          if (unreadable) {
            verdict = "unverified";
            findings.push(stuck(next, (reason = `record ${next} could not be read`)));
            break;
          }
          if (!seals.length) break;
          ({ o, body } = seals[0]);
        } else if (cands.length > 1) {
          // Before records were signed nothing tells which copy is the recorder's: none counts, and reading goes on.
          findings.push({ id: `duplicate-number:${next}`, text: `${cands.length} objects share record number ${next}, from before records were signed: none counts; something wrote around the recorder` });
          seq = next;
          checked++;
          continue;
        }
        const m = nameOf(o.key)!;
        const grant = m.grant, stage = m.stage;
        const shown = await fp(grant);
        try {
          if (body === undefined && o.size > MAX_STORED_BYTES) {
            findings.push({ id: `bad:${next}`, text: `record ${next} (${shown}/${stage}): ${o.size} bytes, over ${MAX_STORED_BYTES}` });
            body = null;
          } else if (body === undefined) {
            body = await env.RECORDS.get(o.key).then((b) => (b ? b.text() : null), () => null);
            if (body === null) {
              // Stop here and read it again next hour: the bookmark never passes a record not checked.
              verdict = "unverified";
              findings.push(stuck(next, (reason = `record ${next} could not be read`)));
              break;
            }
          }
          if (body !== null) {
            const r = await checkStored(next, grant, stage, o.uploaded, body);
            if (r.finding) {
              findings.push(r.finding);
              if (stage === "op") findings.push(await badOp(next, grant)); // never covered (X1)
            } else if (isOpStage(stage)) {
              // Op times are the signed recorded_at alone (W1); the op chain never touches the grant map.
              const t = Date.parse(r.env!.recorded_at);
              const job = (g: string) => (Object.hasOwn(open, g) ? open[g].job : undefined);
              findings.push(...(stage === "op" ? await onOp(ops, next, r.record as unknown as Op, r.env!.sha256, t, job, opsFrom ?? undefined) : await onResult(ops, next, r.record as unknown as OpResult, t)));
            } else {
              // Signed time, so tap reservation ages match the recorder (W1; Codex r1 #2).
              const f = checkOrder(open, grant, stage, r.job!, r.request, r.env!.sha256, Date.parse(r.env!.recorded_at), next, shown);
              if (f) findings.push(f);
              else if (stage === "request") onRequest(ops, grant, next, r.env!.sha256, r.job!, r.record!, Date.parse(r.env!.recorded_at));
              else if (stage === "approval") onApproval(ops, grant, r.request);
            }
          }
        } catch {
          findings.push({ id: `bad:${next}`, text: `record ${next} (${shown}/${stage}): could not be checked` });
        }
        seq = next;
        const d = day(o.uploaded);
        if (isOpStage(stage)) ops.days[d] = (ops.days[d] ?? 0) + 1; // each pool counted apart
        else days[d] = (days[d] ?? 0) + 1;
        countBytes(ops, d, o.size, isOpStage(stage));
        checked++;
      }
      if (checked === PAGE && verdict === "ran") findings.push({ id: `backlog:${day(now)}`, text: `${PAGE} new records in an hour, over what the recorder can take: the rest are read next hour` });
      findings.push(...(await strays(env.RECORDS)));
      if (now.getUTCHours() === SWEEP_HOUR) {
        const s = await sweep(env.RECORDS, key, from, seq, now);
        swept = s.found;
        cleared = s.cleared;
        if (s.incomplete) (verdict = "unverified"), (reason = s.incomplete);
        else ops.written = s.bytes; // the daily count's exact total replaces the hourly sum
      }
    } catch {
      verdict = "unverified";
      reason = "the records could not be listed";
    }
  }
  for (const [d, n] of Object.entries(days)) if (n > DAY_CAP) findings.push({ id: `cap:${d}`, text: `${n} records stored on ${d}, over the cap of ${DAY_CAP}` });
  // Run ops: a complete read moves the watermark (W4); then pools, the op day cap and storage (W8, X4).
  findings.push(...(await settle(ops, now.getTime(), verdict === "ran" && checked < PAGE && ended && tailClear)));
  const use = poolUse(now.getTime(), { tap: days[day(now)] ?? 0, op: ops.days[day(now)] ?? 0 }, Object.values(open).map((g) => ({ opened: g.at, stored: g.stages.length })), Object.values(ops.open));
  findings.push(...poolFindings(ops, day(now), use, DAY_CAP), ...capacityFindings(ops, now.getTime(), use.reserved_bytes));
  pruneDays(ops, now.getTime());
  findings.push(...swept);
  // Only numbers the main read itself checked under the key join the signed range; never after a
  // re-check that stopped short (it would mark unchecked numbers as signed).
  if (key && sealDone) sealedTo = Math.max(sealedTo, seq);
  // Forget grants past their life, keeping at most MAX_OPEN, and day counts older than three days.
  for (const [g, o] of Object.entries(open)) if (now.getTime() - o.at > GRANT_TTL_MS + 86_400_000) delete open[g];
  for (const g of Object.keys(open).sort((a, b) => open[a].at - open[b].at).slice(0, Math.max(0, Object.keys(open).length - MAX_OPEN))) delete open[g];
  for (const d of Object.keys(days)) if (d < day(new Date(now.getTime() - 3 * 86_400_000))) delete days[d];

  const lock = await readLockLength(env, fetchFn, now, RECORDS_BUCKET, LOCKED, MIN_LOCK_SECONDS);
  // No lock evidence is never fine: until LOCK_READ_TOKEN is set, that is a standing incident.
  if (lock.verdict !== "ok") findings.push({ id: `lock:${lock.verdict}`, text: "reason" in lock ? `records lock: ${lock.reason}` : "records lock not checked: LOCK_READ_TOKEN is not set yet" });

  // The standing list. A full run (read everything, under the hourly page) removes the rechecked
  // kinds it no longer finds; nothing else ever removes an entry, and nobody can mark one seen.
  const full = verdict === "ran" && checked < PAGE, today = day(now);
  const legacy = new Set(Array.isArray(prev.alerted) ? prev.alerted : []);
  const list = new Map<string, Incident>();
  const kept = [...(Array.isArray(prev.incidents) ? prev.incidents : []), ...(Array.isArray(prev.queued) ? prev.queued : [])] as Partial<Incident>[];
  for (const i of kept) if (isFinding(i) && !OLD_FOREIGN.test(i.id) && !list.has(i.id)) list.set(i.id, { id: i.id, text: i.text, since: typeof i.since === "string" ? i.since : today, told: i.told === true });
  // Incidents the list had no room for, by id only: Ben hears of them through one overflow line,
  // which alerts again whenever an id joins the set (or the uncounted rest grows).
  const lastMore = list.get("incidents:more");
  list.delete("incidents:more");
  const before = new Set(Array.isArray(prev.dropped) ? prev.dropped.filter((x): x is string => typeof x === "string") : []);
  const dropped = new Set(before), fullBefore = prev.droppedFull === true;
  let droppedFull = fullBefore;
  const found = new Set(findings.map((f) => f.id));
  // A daily-count problem about one number leaves only when a daily count read that number and found
  // it clear: not being looked at, or being cut by a cap, is never taken as resolved (Codex r2 #4, r3 #1).
  const clear = (id: string) => Number.isNaN(numberOf(id)) || cleared.has(numberOf(id));
  if (full) for (const id of [...list.keys(), ...dropped]) if (RECHECKED.has(kind(id)) && !found.has(id) && clear(id)) list.delete(id), dropped.delete(id);
  // Found again: same entry (same since, same told), latest wording. A dropped id found again was
  // already counted in the overflow line, so it is as told as that line.
  for (const f of findings) list.set(f.id, list.has(f.id) ? { ...list.get(f.id)!, text: f.text } : { ...f, since: today, told: legacy.has(f.id) || (dropped.has(f.id) && lastMore?.told === true) });
  // Over the bound: serious kinds first, told or not; among junk and stray, untold before told, so
  // a flood of junk can push out only older junk; among serious kinds of one rank, untold first.
  let listed = [...list.values()].sort((x, y) => Number(rank(x) >= LOW) - Number(rank(y) >= LOW) || (rank(x) >= LOW ? Number(x.told) - Number(y.told) : 0) || rank(x) - rank(y) || Number(x.told) - Number(y.told));
  const room = dropped.size || droppedFull || listed.length > MAX_INCIDENTS ? MAX_INCIDENTS - 1 : MAX_INCIDENTS;
  for (const i of listed.slice(room)) dropped.add(i.id);
  listed = listed.slice(0, room);
  for (const i of listed) dropped.delete(i.id);
  // Past MAX_DROPPED the least serious ids are let go (oldest first among equals), so a new serious
  // problem still joins and alerts, and a junk name found again cannot churn. Once that happens the
  // checker can no longer tell every new problem from an old one: the line says so for good.
  if (dropped.size > MAX_DROPPED) {
    const keep = [...dropped].sort((x, y) => rank({ id: x, text: "" }) - rank({ id: y, text: "" })).slice(0, MAX_DROPPED);
    dropped.clear();
    for (const id of keep) dropped.add(id);
    droppedFull = true;
  }
  if (dropped.size || droppedFull) {
    const grew = droppedFull !== fullBefore || [...dropped].some((id) => !before.has(id));
    listed.push({ id: "incidents:more", text: droppedFull ? `over ${MAX_DROPPED} more incidents could not be kept, and new ones past that cannot be told apart: read the records` : `${dropped.size} more incidents could not be kept: read the records`, since: lastMore?.since ?? today, told: lastMore?.told === true && !grew });
  }
  listed.sort((x, y) => rank(x) - rank(y));
  const fresh = listed.filter((i) => !i.told);
  const ping = env.PING_URL_RECORDS;

  // Until Ben creates this job's check, it only logs (like fresh.ts): no alert, no light.
  let unverifiedTold = verdict === "unverified" && (prev.unverifiedTold === true || legacy.has("unverified"));
  let reminded = typeof prev.reminded === "string" ? prev.reminded : undefined;
  if (ping) {
    // At most one alert a run, worst first. Its fallback is the light's own check, and healthchecks
    // emails only when a check changes state (Codex r1 #2, from its source), so a second /fail, or
    // a /fail while the light is already red, may email nothing.
    const lines: string[] = [], sent: Incident[] = [];
    const remind = listed.length > 0 && now.getUTCDay() === REMIND_DAY && now.getUTCHours() >= REMIND_HOUR && reminded !== today;
    if (verdict === "unverified" && !unverifiedTold) lines.push(`The records check could not finish: ${reason}`.slice(0, 300));
    for (const i of fresh) {
      if ([...lines, i.text.slice(0, 300)].join("\n").length > 800) break;
      lines.push(i.text.slice(0, 300));
      sent.push(i);
    }
    if (sent.length < fresh.length) lines.push(`(+${fresh.length - sent.length} more new, sent next hour)`);
    // The weekly reminder: one line.
    if (remind) lines.push(`${listed.length} open records incident${listed.length === 1 ? "" : "s"}: ${listed[0].text.slice(0, 150)}, since ${listed[0].since}${listed.length > 1 ? `; +${listed.length - 1} more` : ""}`);
    if (lines.length) {
      const title = verdict === "unverified" && !unverifiedTold ? "Observatory: the records check could not finish" : sent.length ? `Observatory: ${sent.length} new records incident${sent.length === 1 ? "" : "s"}` : "Observatory: open records incidents this week";
      // A run that read everything turns the light green first, so a fallback /fail is a change that emails.
      // Only a confirmed green makes the fallback /fail a change (Codex r2 new #1).
      const green = verdict === "ran" && (await fetchFn(new Request(ping, { method: "POST", body: "run complete; an alert follows" })).then((r) => r.ok, () => false));
      const via = await alert({ ...env, PING_URL: ping }, fetchFn, title, lines.join("\n"));
      // On an unverified run the light may already be red: only Pushover counts as delivered.
      if (via === "pushover" || (via === "healthchecks" && green)) {
        for (const i of sent) i.told = true;
        if (remind) reminded = today;
      }
      if (via === "pushover" && verdict === "unverified") unverifiedTold = true;
    }
  }
  if (verdict === "ran") reason = `${checked} new records read; ${listed.length} open incident${listed.length === 1 ? "" : "s"}${listed.length ? `: ${listed.map((i) => i.text).join("; ")}` : ""}`;
  try {
    await env.COPY.put(STATE_KEY, JSON.stringify({ sealed: key ? { key: pin!.key, to: sealedTo } : undefined, seq, open, days, swept, incidents: listed, dropped: [...dropped], droppedFull, unverifiedTold, reminded, ops } satisfies State));
  } catch {
    reason = `records state could not be saved; ${reason}`;
    verdict = "unverified";
  }

  // The light: "the checker ran and read what it should", never "the records are fine".
  const report = { records: verdict, checked, seq, open: listed.length, new: fresh.length, lock: lock.verdict, ops: measures(ops, use, day(now)), reason: redact(reason, env).slice(0, 2000), setup: ping ? "complete" : "PING_URL_RECORDS not set: log only" };
  console.log(JSON.stringify(report));
  if (ping) await fetchFn(new Request(verdict === "ran" ? ping : `${ping}/fail`, { method: "POST", body: JSON.stringify(report) })).catch(() => undefined);
  return report;
}
