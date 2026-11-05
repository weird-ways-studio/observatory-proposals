// The recorder's core (card feea07eb, route A). One instance runs inside one Durable Object
// (src/recorder/index.ts), so every write in the Observatory goes through this queue in turn.
// It decides, before anything is stored: is the record in the contract, is its stage in order for
// its grant, is there room today and in the storage budget. Then it saves the record as pending,
// writes it to the locked bucket, and only then answers with a receipt. A crash between those
// steps leaves the pending record, which the next call finishes first -- so sequence numbers never
// have gaps. Every envelope is signed (card 6a04908f) with a key made here on first use; the
// private half lives only in this Durable Object's storage and is never returned or logged.
// An `approval` is stored only if Ben's pinned passkey signed it for that grant (passkey.ts, card 7190ab0a).
// Since card 8ff5110b (B2) it also stores run ops: an `op` only when Ben's passkey-approved run covers it
// (the run-open grant's `g:` entry holds the run), and one `op_result` per op; op state lives under `o:`.
import { b64, DAY_CAP, GRANT_TTL_MS, keyFor, MAX_STORED_BYTES, sealed, sha256, SKEW_MS, STAGE_SLOTS, STORE_BUDGET_BYTES, unb64, validate, type Envelope, type Receipt, type Stage } from "../contract.ts";
import { approvalCheck, grantHashOf, PASSKEY_PIN, type ApprovalCheck } from "./passkey.ts";
import { isOpStage, OP_DAY_CAP, opKeyFor, OPS_FROM, parseDescriptor, RESULT_MS, RUN_CUTOFF_BYTES, RUN_OPEN_JOB, uncovered, validateOp, type Descriptor, type Op } from "../ops.ts";

/**
 * The off switch for run ops (REFINE-observatory-ops.md v2 V2). A one-line PR setting it false (Ben merges)
 * makes the recorder refuse every new `op` (403) while results, pending writes and taps go on. Once a
 * run-open request has been admitted, this switch is the rollback lever, never a revert (v14 CC5).
 */
export const OPS_ENABLED = true;

/**
 * The slice of Durable Object storage used here; each put of several keys is one atomic write.
 * `transaction` runs `fn` so that every put and delete inside it lands together or not at all (a
 * throw inside `fn` discards them all). Used where two writes must never be seen apart: a withdrawal's
 * accounting and the removal of `pending` (REFINE-observatory-ops.md v11 AE1). The live object passes
 * Cloudflare's own `ctx.storage` (index.ts); test/recorder.workerd.test.ts proves the all-or-nothing
 * behaviour in the real runtime, and test/store.ts mirrors it for the fast tests.
 */
export interface Txn {
  get<T>(key: string): Promise<T | undefined>;
  put(entries: Record<string, unknown>): Promise<void>;
  delete(key: string): Promise<boolean>;
}
export interface Storage extends Txn {
  transaction<T>(fn: (txn: Txn) => Promise<T>): Promise<T>;
}
export type Bucket = Pick<R2Bucket, "get" | "put">;

// Two pools of DAY_CAP / OP_DAY_CAP slots a UTC day (card 509a5d85): taps (Ben's grants) and run ops,
// so run traffic can never take the room Ben's taps need. The state is additive over 43af20c: the tap
// pool keeps its old names (`used`, `open`), the op pool and counters are new optional fields, and old
// code ignores and keeps them (REFINE-observatory-ops.md v5 Y2, v6 Z6). B2 (card 8ff5110b) admits ops into
// the op pool; old code would not know the run and op state, so after B2 the off switch replaces a revert.
//
// An open grant still holds `left` reserved slots for its later stages, whatever day they land on,
// until `opened` + 24 h (inclusive); an op holds 1 for its result until `at` + 24 h. A hold that runs
// out is released on the next accept or status read (`settle`), counted once in `expired`.
interface Open { grant: string; opened: number; left: number }
interface OpOpen { op: string; at: number; left: number }
// `used` / `op_used`: today's slots per pool = records charged today + every hold still open (carried
// in at rollover, released at expiry). `bytes`: every stored or pending envelope's size, for the budget.
// `op_peak`: the op pool's highest use on `day`; `op_peak_prev`: the same for the previous day with a turn (v14 CC6).
interface Meta { seq: number; day: string; used: number; bytes: number; open: Open[]; op_used?: number; op_open?: OpOpen[]; expired?: { tap: number; op: number }; op_peak?: number; op_peak_prev?: number }
// `grant_hash`: the front desk's hash of the grant, kept only if it matches the hash worked out here from
// the request's own fields (passkey.ts grantHashOf); Ben's passkey answer must carry it.
// A run-open grant (job `cf.run.open`) is also a run (v13 BB3a-b): `descriptor` parsed at its request's
// recorded time; `checked` set only in the same write that queues an approval that passed the passkey
// check, and cleared in the same transaction as any withdrawal of it or a late upload (CC2); `late` when
// its request's object reached the bucket over SKEW_MS after its recorded time (DD1); `ops` = unique ops
// admitted (+1 with each op's pending write, -1 only if that op is withdrawn).
interface Grant { job: string; request: string; opened: number; grant_hash?: string; stages: Partial<Record<Stage, Receipt>>; descriptor?: Descriptor; checked?: boolean; late?: boolean; ops?: number }
/**
 * One op, under `o:<op id>` (BB3b, CC3). `state`: `open` until a result is queued, `redeemed` with its
 * result, `released` if that result was withdrawn late. Expiry writes nothing here: an `open` op with no
 * hold, over 24 h old, has expired. A withdrawn op has no entry at all.
 */
interface OpState { run_grant: string; sha: string; at: number; job: string; run: string; receipt: Receipt; result?: Receipt; state: "open" | "redeemed" | "released" }
// `day`: the UTC day its slot was charged to. `pool`: absent = tap (every record before B2).
interface Pending { key: string; stored: string; storedSha: string; receipt: Receipt; day: string; pool?: "tap" | "op" }
interface Keys { priv: string; pub: string } // base64 PKCS#8 and raw Ed25519 public key
// Refusals by fixed reason word, and identical retries answered with the stored receipt (status only).
// B2 adds four (BB3f): ops refused by a full op pool, the 5 GiB cutoff, no covering run, or the off switch.
export const REFUSALS = ["invalid", "conflict", "late", "tap_pool_full", "budget_full", "stuck", "op_pool_full", "run_cutoff", "uncovered", "switched_off"] as const;
type Refusal = (typeof REFUSALS)[number];
// `runs`: run-open requests ever admitted (pending or stored); above 0, a revert is no longer safe (CC5).
interface Counters { refused: Partial<Record<Refusal, number>>; retries: number; runs?: number }

/** `reason` names the counter for a refusal whose status alone does not (the op refusals). */
export type Outcome =
  | { status: 200 | 201; receipt: Receipt }
  | { status: 400 | 403 | 409 | 410 | 429 | 503; why: string; reason?: Refusal };
/** What finishing the pending record came to: stored (neither), withdrawn with fixed words (W3), or stuck. */
interface Finished { stuck?: string; withdrawn?: string }
/** Test seams, defaulting to the reviewed constants: OPS_FROM, the off switch, the op cutoff. */
export interface OpsOptions { opsFrom?: number; opsEnabled?: boolean; cutoff?: number }

const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
const len = (s: string) => new TextEncoder().encode(s).length;
const held = (m: Meta) => ({ tap: m.open.reduce((n, o) => n + o.left, 0), op: (m.op_open ?? []).reduce((n, o) => n + o.left, 0) });
const reservedBytes = (m: Meta) => (held(m).tap + held(m).op) * MAX_STORED_BYTES;
const peak = (m: Meta): Meta => ({ ...m, op_peak: Math.max(m.op_peak ?? 0, m.op_used ?? 0) });
/** The stored name for a record of either kind. */
const nameFor = (seq: number, id: string, stage: Stage | "op" | "op_result", tag?: string) => (isOpStage(stage) ? opKeyFor(seq, id, stage, tag) : keyFor(seq, id, stage, tag));
/** The hold a pending record keeps from expiry: its grant's in the tap pool, or its op's in the op pool (CC1). */
type Keep = { pool: "tap" | "op"; id: string };
const keepOf = (p?: Pending): Keep | undefined => (p ? { pool: p.pool ?? "tap", id: p.receipt.grant } : undefined);
const bodyOf = (p: Pending) => (JSON.parse(p.stored) as Envelope).body;
/** True if the body is JSON naming an op stage; such a body is checked by ops.ts validateOp, never contract validate. */
function opBody(body: string): boolean {
  try {
    const r = JSON.parse(body);
    return Boolean(r) && typeof r === "object" && isOpStage((r as { stage?: unknown }).stage as string);
  } catch {
    return false;
  }
}
/** A run-open request's descriptor (Y4): params exactly `{descriptor}`, parsed at the request's own time; else fixed words. */
function runDescriptor(r: Record<string, unknown>, at: number): Descriptor | string {
  const p = r.params;
  if (!p || typeof p !== "object" || Array.isArray(p) || Object.keys(p).length !== 1 || !Object.hasOwn(p, "descriptor")) return "a run-open request's params must be exactly the descriptor";
  return parseDescriptor((p as Record<string, unknown>).descriptor, at);
}

/**
 * Brings the counts to time `t`: holds past their 24 h are released (taken off today's pool and
 * counted once in `expired`), then a new UTC day starts with the holds still open, never at zero.
 * `keep` names the pending record's hold, by pool and id, which is never released while it is pending
 * (REFINE v6 Z4): it is re-timed or withdrawn by #finishPending instead. A grant and an op may share an
 * id, so only the hold in `keep.pool` is kept (v14 CC1).
 */
function settle(m: Meta, t: number, keep?: Keep): Meta {
  const expired = { tap: m.expired?.tap ?? 0, op: m.expired?.op ?? 0 };
  let used = m.used, opUsed = m.op_used ?? 0;
  const open = m.open.filter((o) => {
    if (o.left <= 0 || (keep?.pool === "tap" && o.grant === keep.id) || t - o.opened <= GRANT_TTL_MS) return true;
    used -= o.left;
    expired.tap += 1;
    return false;
  });
  const opOpen = (m.op_open ?? []).filter((o) => {
    if (o.left <= 0 || (keep?.pool === "op" && o.op === keep.id) || t - o.at <= RESULT_MS) return true;
    opUsed -= o.left;
    expired.op += 1;
    return false;
  });
  const next: Meta = { ...m, used, open, op_used: opUsed, op_open: opOpen, expired };
  if (m.day === day(t)) return next;
  const carry = open.filter((o) => o.left > 0), opCarry = opOpen.filter((o) => o.left > 0);
  const opUsedNew = held({ ...next, op_open: opCarry }).op;
  return { ...next, day: day(t), open: carry, used: held({ ...next, open: carry }).tap, op_open: opCarry, op_used: opUsedNew, op_peak: opUsedNew, op_peak_prev: Math.max(m.op_peak ?? 0, m.op_used ?? 0) };
}

/** Admits, orders and stores records one at a time; see the file comment. */
export class Ledger {
  #queue: Promise<unknown> = Promise.resolve();
  #key?: { priv: CryptoKey; pub: string };
  private storage: Storage;
  private bucket: Bucket;
  private budget: number;
  private approvals: ApprovalCheck;
  #opsFrom: number | undefined;
  #opsEnabled: boolean;
  #cutoff: number;
  constructor(storage: Storage, bucket: Bucket, budget = STORE_BUDGET_BYTES, approvals = approvalCheck(PASSKEY_PIN), ops: OpsOptions = {}) {
    this.storage = storage;
    this.bucket = bucket;
    this.budget = budget;
    this.approvals = approvals;
    this.#opsFrom = "opsFrom" in ops ? ops.opsFrom : OPS_FROM;
    this.#opsEnabled = ops.opsEnabled ?? OPS_ENABLED;
    this.#cutoff = ops.cutoff ?? RUN_CUTOFF_BYTES;
  }

  /**
   * One write at a time, in arrival order: a later call waits for the one before to finish. The
   * time is read when its turn comes, so recorded times rise with sequence numbers.
   */
  accept(body: string, clock: () => Date = () => new Date()): Promise<Outcome> {
    return this.#serial(async () => this.#count(await this.#accept(body, clock())));
  }

  /** Counts a refusal by its reason word, or an identical retry; returns the outcome unchanged. */
  async #count(out: Outcome): Promise<Outcome> {
    const reason = "reason" in out && out.reason ? out.reason : out.status === 400 ? "invalid" : out.status === 409 ? "conflict" : out.status === 410 ? "late" : out.status === 503 ? "stuck"
      : out.status === 429 ? (out.why.startsWith("the recorder's storage budget") ? "budget_full" : "tap_pool_full") : undefined;
    if (!reason && out.status !== 200) return out;
    const c = (await this.storage.get<Counters>("counters")) ?? { refused: {}, retries: 0 };
    if (reason) c.refused[reason] = (c.refused[reason] ?? 0) + 1;
    else c.retries += 1;
    await this.storage.put({ counters: c });
    return out;
  }

  /** Runs `fn` after every call queued before it: records, status and key creation never overlap. */
  #serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(fn);
    this.#queue = run.catch(() => undefined);
    return run;
  }

  /**
   * Today's use of each pool, holds, the storage budget, whether a write is pending, refusals, and
   * the public key the checker pins (made here if none exists yet, so it can be pinned before the
   * first record). The time is read when its turn comes (REFINE v6 Z5), and holds past their 24 h are
   * shown released (the next accept stores that), so status never shows a hold the checker has already
   * let go. Status writes nothing. Older names stay
   * (`used_today` = the tap pool) so the front desk's reader is unchanged.
   */
  status(clock: () => Date = () => new Date()) {
    return this.#serial(async () => {
      const now = clock(); // a clock, never a time: a Date taken before the queue goes stale behind a stalled write (Codex B1 r1 #1)
      const pending = await this.storage.get<Pending>("pending");
      const stored = await this.storage.get<Meta>("meta");
      const meta = stored ? settle(stored, now.getTime(), keepOf(pending)) : undefined;
      const c = (await this.storage.get<Counters>("counters")) ?? { refused: {}, retries: 0 };
      const h = meta ? held(meta) : { tap: 0, op: 0 };
      return {
        seq: meta?.seq ?? 0, used_today: meta?.used ?? 0, cap: DAY_CAP, stored_bytes: meta?.bytes ?? 0, budget_bytes: this.budget, pending: Boolean(pending), public_key: (await this.#keys()).pub,
        pools: {
          tap: { used: meta?.used ?? 0, cap: DAY_CAP, reserved_slots: h.tap, reserved_bytes: h.tap * MAX_STORED_BYTES },
          op: { used: meta?.op_used ?? 0, cap: OP_DAY_CAP, reserved_slots: h.op, reserved_bytes: h.op * MAX_STORED_BYTES },
        },
        op_cutoff_bytes: RUN_CUTOFF_BYTES, pending_bytes: pending ? len(pending.stored) : 0,
        refused: Object.fromEntries(REFUSALS.map((r) => [r, c.refused[r] ?? 0])), retries: c.retries, expired: meta?.expired ?? { tap: 0, op: 0 },
        // B2 (v14 CC5-CC6): the switch, the first record number whose runs may cover ops, run-open requests
        // admitted (above 0, roll back with the switch, never a revert), and the op pool's daily peak.
        ops: { enabled: this.#opsEnabled, from: this.#opsFrom ?? null, runs_admitted: c.runs ?? 0 },
        op_peak: meta?.op_peak ?? 0, op_peak_prev: meta?.op_peak_prev ?? 0,
      };
    });
  }

  /** The signing key: loaded, or made once and kept. Only ever called inside the queue. */
  async #keys() {
    if (this.#key) return this.#key;
    let k = await this.storage.get<Keys>("signing");
    if (!k) {
      const made = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
      k = { priv: b64((await crypto.subtle.exportKey("pkcs8", made.privateKey)) as ArrayBuffer), pub: b64((await crypto.subtle.exportKey("raw", made.publicKey)) as ArrayBuffer) };
      await this.storage.put({ signing: k });
    }
    this.#key = { priv: await crypto.subtle.importKey("pkcs8", unb64(k.priv), "Ed25519", false, ["sign"]), pub: k.pub };
    return this.#key;
  }

  /** The envelope as stored: version 2, signed over every other field. */
  async #seal(e: Envelope): Promise<string> {
    const v2: Envelope = { ...e, v: 2 };
    const sig = await crypto.subtle.sign("Ed25519", (await this.#keys()).priv, sealed(v2));
    return JSON.stringify({ ...v2, sig: b64(sig) });
  }

  /** One record's turn: finish any pending write, check, reserve, queue, store, receipt. */
  async #accept(body: string, now: Date): Promise<Outcome> {
    // An unfinished write always goes first; until it is stored nothing new is taken. Its own outcome
    // (stored or withdrawn) went to nobody: no receipt was sent for it, so the desk retries or stops.
    const first = await this.#finishPending(now);
    if (first.stuck) return { status: 503, why: first.stuck };
    if (opBody(body)) return this.#acceptOp(body, now);

    const checked = validate(body);
    if (!checked.ok) return { status: 400, why: checked.why };
    const r = checked.record, sha = await sha256(body), t = now.getTime();
    const grant = await this.storage.get<Grant>(`g:${r.grant}`);

    const done = grant?.stages[r.stage];
    if (done) {
      // The same bytes again (a lost answer, retried) get the same receipt; anything else is refused.
      return done.sha256 === sha ? { status: 200, receipt: done } : { status: 409, why: "this stage of this grant is already recorded with other content" };
    }
    let meta = settle((await this.storage.get<Meta>("meta")) ?? { seq: 0, day: day(t), used: 0, bytes: 0, open: [] }, t);

    let next: Grant, counters: Counters | undefined;
    if (r.stage === "request") {
      // A run-open request carries exactly its descriptor, valid at this record's own time (Y4, BB2.1).
      const descriptor = r.job === RUN_OPEN_JOB ? runDescriptor(r, t) : undefined;
      if (typeof descriptor === "string") return { status: 400, why: descriptor };
      if (meta.used + STAGE_SLOTS > DAY_CAP) return { status: 429, why: `today's ${DAY_CAP} record slots are taken` };
      if (meta.bytes + reservedBytes(meta) + STAGE_SLOTS * MAX_STORED_BYTES > this.budget) return { status: 429, why: "the recorder's storage budget is full: Ben must decide" };
      meta = { ...meta, used: meta.used + STAGE_SLOTS, open: [...meta.open, { grant: r.grant, opened: t, left: STAGE_SLOTS - 1 }] };
      next = { job: r.job, request: sha, opened: t, ...(await grantHashOf(r).then((h) => (h && r.grant_hash === h ? { grant_hash: h } : {}))), stages: {}, ...(descriptor ? { descriptor, ops: 0 } : {}) };
      if (descriptor) {
        counters = (await this.storage.get<Counters>("counters")) ?? { refused: {}, retries: 0 };
        counters = { ...counters, runs: (counters.runs ?? 0) + 1 };
      }
    } else {
      if (!grant) return { status: 409, why: "no request is recorded for this grant" };
      if (t - grant.opened > GRANT_TTL_MS) return { status: 410, why: "this grant's request is over 24 hours old" };
      if (r.request !== grant.request) return { status: 409, why: "the request hash does not match the recorded request" };
      if (r.job !== grant.job) return { status: 409, why: "the job does not match the recorded request" };
      if (r.stage === "result" && !grant.stages.approval) return { status: 409, why: "no approval is recorded for this grant" };
      const run = grant.job === RUN_OPEN_JOB;
      if (r.stage === "approval") {
        // A run is approved only over a request stored on time with a descriptor this recorder parsed (CC4, DD1).
        if (run && grant.late) return { status: 409, why: "the run-open request was stored late; open a new run" };
        if (run && !grant.descriptor) return { status: 409, why: "the run-open request has no descriptor this recorder checked; open a new run" };
        const refused = await this.approvals(r, grant.grant_hash);
        if (refused) return { status: 409, why: refused };
      }
      // Its slot was reserved when the request was taken (and carried into today if need be).
      meta = { ...meta, open: meta.open.map((o) => (o.grant === r.grant ? { ...o, left: Math.max(0, o.left - 1) } : o)) };
      // BB3a: `checked` rides in the same write that queues the approval, never a later one.
      next = run && r.stage === "approval" ? { ...grant, checked: true } : grant;
    }

    const seq = meta.seq + 1, key = keyFor(seq, r.grant, r.stage);
    const receipt: Receipt = { v: 1, seq, key, grant: r.grant, stage: r.stage, sha256: sha, recorded_at: now.toISOString() };
    const stored = await this.#seal({ v: 2, seq, grant: r.grant, stage: r.stage, recorded_at: receipt.recorded_at, sha256: sha, body });
    const pending: Pending = { key, stored, storedSha: await sha256(stored), receipt, day: meta.day };
    // Counted, ordered and queued in one atomic step, before the bucket is touched.
    await this.storage.put({
      meta: { ...meta, seq, bytes: meta.bytes + len(stored) },
      [`g:${r.grant}`]: { ...next, stages: { ...next.stages, [r.stage]: receipt } },
      pending,
      ...(counters ? { counters } : {}),
    });
    return this.#finish(now, async () => (await this.storage.get<Grant>(`g:${r.grant}`))?.stages[r.stage]);
  }

  /**
   * An `op` or `op_result` (card 8ff5110b). An op is taken only when its run covers it: the V3.1
   * prerequisites, then `uncovered()` from ops.ts at this record's time (Z7, the checker's own rule). It
   * charges its slot and reserves one for its result in the op pool, and only below the 5 GiB cutoff. A
   * result needs none of that (its slot is reserved): it must name its op's exact bytes, run and job,
   * within 24 h of the op, once. The off switch stops new ops only (V2).
   */
  async #acceptOp(body: string, now: Date): Promise<Outcome> {
    const checked = validateOp(body);
    if (!checked.ok) return { status: 400, why: checked.why };
    const r = checked.record, sha = await sha256(body), t = now.getTime(), ok = `o:${r.grant}`;
    const o = await this.storage.get<OpState>(ok);
    let meta = settle((await this.storage.get<Meta>("meta")) ?? { seq: 0, day: day(t), used: 0, bytes: 0, open: [] }, t);
    const entries: Record<string, unknown> = {};
    if (r.stage === "op") {
      // An identical retry is answered before anything is counted, so it never takes a budget unit (T7).
      if (o) return o.receipt.sha256 === sha ? { status: 200, receipt: o.receipt } : { status: 409, why: "this op is already recorded with other content" };
      if (!this.#opsEnabled) return { status: 403, why: "run operations are switched off", reason: "switched_off" };
      const run = await this.storage.get<Grant>(`g:${r.run_grant}`);
      const why = this.#notCovered(r, run, t, 0);
      if (why) return { status: 409, why, reason: "uncovered" };
      if ((meta.op_used ?? 0) + 2 > OP_DAY_CAP) return { status: 429, why: `today's ${OP_DAY_CAP} op slots are taken`, reason: "op_pool_full" };
      // Ops stop below the cutoff, counting its own two slots, so the last GiB stays Ben's (BB2.4).
      if (meta.bytes + reservedBytes(meta) + 2 * MAX_STORED_BYTES > Math.min(this.#cutoff, this.budget)) return { status: 429, why: "run operations stop at the storage cutoff; the rest is kept for Ben's taps", reason: "run_cutoff" };
      meta = { ...meta, op_used: (meta.op_used ?? 0) + 2, op_open: [...(meta.op_open ?? []), { op: r.grant, at: t, left: 1 }] };
      entries[`g:${r.run_grant}`] = { ...run!, ops: (run!.ops ?? 0) + 1 };
    } else {
      if (!o) return { status: 409, why: "no op is recorded under this id" };
      if (o.result) return o.result.sha256 === sha ? { status: 200, receipt: o.result } : { status: 409, why: "this op already has a result with other content" };
      // `released`: a result was withdrawn late, so the op's 24 h are over too (CC3); inclusive at 24 h, as poolUse.
      if (o.state === "released" || t - o.at > RESULT_MS) return { status: 410, why: "this op's result is over 24 hours late" };
      if (r.op !== o.sha || r.run !== o.run || r.job !== o.job) return { status: 409, why: "the result does not name its op's exact record, run and job" };
      meta = { ...meta, op_open: (meta.op_open ?? []).map((h) => (h.op === r.grant ? { ...h, left: Math.max(0, h.left - 1) } : h)) };
    }
    const seq = meta.seq + 1, key = opKeyFor(seq, r.grant, r.stage);
    const receipt: Receipt = { v: 1, seq, key, grant: r.grant, stage: r.stage, sha256: sha, recorded_at: now.toISOString() };
    const stored = await this.#seal({ v: 2, seq, grant: r.grant, stage: r.stage, recorded_at: receipt.recorded_at, sha256: sha, body });
    entries[ok] = r.stage === "op" ? { run_grant: r.run_grant, sha, at: t, job: r.job, run: r.run, receipt, state: "open" } satisfies OpState : { ...o!, result: receipt, state: "redeemed" } satisfies OpState;
    const pending: Pending = { key, stored, storedSha: await sha256(stored), receipt, day: meta.day, pool: "op" };
    await this.storage.put({ meta: peak({ ...meta, seq, bytes: meta.bytes + len(stored) }), ...entries, pending });
    return this.#finish(now, async () => {
      const after = await this.storage.get<OpState>(ok);
      return r.stage === "op" ? after?.receipt : after?.result;
    });
  }

  /** Stores the turn's own pending record and answers: its receipt, 410 with the withdrawal's words, or 503. */
  async #finish(now: Date, receiptOf: () => Promise<Receipt | undefined>): Promise<Outcome> {
    const done = await this.#finishPending(now);
    if (done.stuck) return { status: 503, why: done.stuck };
    if (done.withdrawn) return { status: 410, why: done.withdrawn };
    const final = await receiptOf();
    return final ? { status: 201, receipt: final } : { status: 410, why: "the record was withdrawn before it was stored" };
  }

  /**
   * Why `run` does not cover `op` at time `at`, or undefined. The V3.1 prerequisites first (Z7): a
   * run-open grant with its request, a descriptor this recorder parsed, an approval this recorder
   * passkey-checked and a request stored on time; then ops.ts `uncovered()` (OPS_FROM, descriptor
   * scope, deadline, budget). `self` = 1 when re-checking a pending op, which is already in `ops`.
   */
  #notCovered(op: Op, run: Grant | undefined, at: number, self: 0 | 1): string | undefined {
    if (!run || run.job !== RUN_OPEN_JOB || !run.stages.request || !run.descriptor) return "it names no run-open request this recorder checked";
    if (!run.stages.approval || run.checked !== true || run.late) return "its run has no approval that passed the checks";
    return uncovered(op, { seq: run.stages.request.seq, sha: run.request, descriptor: run.descriptor, approved: true, ops: (run.ops ?? 0) - self }, at, this.#opsFrom);
  }

  /**
   * Withdraws a pending approval whose passkey answer fails the check: its number, bytes and grant
   * stage are given back, so the next record takes the number and no gap appears. No receipt has gone
   * out for it (receipts follow storage), so the desk has already stopped that grant. Returns true if
   * withdrawn. The accounting and the removal of `pending` are one transaction (REFINE v11 AE1): after
   * any crash the state is wholly before (pending still there, handled as today) or wholly after. Before
   * card 509a5d85 they were two writes, and a crash and a planted object between them let #retag put
   * back a receipt for a record never written (Codex r5 on B1's refinement). A run's `checked` goes in
   * the same transaction (BB3a).
   */
  async #withdrawUnverified(p: Pending, now: number): Promise<boolean> {
    const checked = validate(bodyOf(p));
    const g0 = (await this.storage.get<Grant>(`g:${p.receipt.grant}`))!;
    if (checked.ok && !(await this.approvals(checked.record, g0.grant_hash))) return false;
    await this.storage.transaction(async (txn) => {
      const m = settle((await txn.get<Meta>("meta"))!, now, keepOf(p)), g = (await txn.get<Grant>(`g:${p.receipt.grant}`))!;
      if (m.seq === p.receipt.seq) {
        const { approval: _, ...stages } = g.stages, hold = m.open.some((o) => o.grant === p.receipt.grant);
        const { checked: _c, ...rest } = g;
        await txn.put({
          // Its slot goes back to the grant's hold. Charged on an earlier day, that hold is new to
          // today's pool, so today counts it (else today's pool reads one low; found writing B1).
          // With no hold left to return it to, today simply loses its charge if it was charged today.
          meta: { ...m, seq: m.seq - 1, bytes: Math.max(0, m.bytes - len(p.stored)), used: m.used + (hold ? (p.day === m.day ? 0 : 1) : (p.day === m.day ? -1 : 0)), open: m.open.map((o) => (o.grant === p.receipt.grant ? { ...o, left: o.left + 1 } : o)) },
          [`g:${p.receipt.grant}`]: { ...rest, stages },
        });
      }
      await txn.delete("pending");
    });
    return true;
  }

  /**
   * Withdraws a pending later tap stage that would be stored past its grant's 24 h (REFINE v7 AA2, v8
   * AB2): the stage is taken off its grant, its number (when still the last) and bytes are given back
   * once, its charge comes off today's pool if it was charged today, and the grant's remaining hold is
   * released as expired (counted once), never restored. One transaction with the removal of `pending`
   * (v11 AE1). Called only once the bucket holds nothing under its exact name (W3). A withdrawn
   * approval takes its run's `checked` with it (BB3a).
   */
  async #withdrawLate(p: Pending, now: number): Promise<void> {
    await this.storage.transaction(async (txn) => {
      const m = settle((await txn.get<Meta>("meta"))!, now, keepOf(p)), g = (await txn.get<Grant>(`g:${p.receipt.grant}`))!;
      const { [p.receipt.stage as Stage]: _, ...stages } = g.stages;
      const { checked: _c, ...rest } = g;
      const hold = m.open.find((o) => o.grant === p.receipt.grant);
      const expired = { ...m.expired!, tap: m.expired!.tap + (hold && hold.left > 0 ? 1 : 0) };
      await txn.put({
        meta: {
          ...m, expired,
          seq: m.seq === p.receipt.seq ? m.seq - 1 : m.seq,
          bytes: Math.max(0, m.bytes - len(p.stored)),
          used: m.used - (p.day === m.day ? 1 : 0) - (hold?.left ?? 0),
          open: m.open.filter((o) => o.grant !== p.receipt.grant),
        },
        [`g:${p.receipt.grant}`]: { ...(p.receipt.stage === "approval" ? rest : g), stages },
      });
      await txn.delete("pending");
    });
  }

  /**
   * The B2 withdrawals (W2, BB3d, CC3): `change` adjusts the pool and the record's own state; this gives
   * back the number (when still the last) and the bytes once, and removes `pending`, all in ONE
   * transaction (AE1). Called only once the bucket holds nothing under the record's exact name (W3).
   */
  async #withdraw(p: Pending, now: number, change: (m: Meta, txn: Txn) => Promise<Meta>): Promise<void> {
    await this.storage.transaction(async (txn) => {
      const m = await change(settle((await txn.get<Meta>("meta"))!, now, keepOf(p)), txn);
      await txn.put({ meta: { ...m, seq: m.seq === p.receipt.seq ? m.seq - 1 : m.seq, bytes: Math.max(0, m.bytes - len(p.stored)) } });
      await txn.delete("pending");
    });
  }

  /** A run-open request not valid at its recorded time (BB3d, CC4): its own slot and whole hold go, and its grant entry. */
  #withdrawRequest(p: Pending, now: number) {
    return this.#withdraw(p, now, async (m, txn) => {
      const hold = m.open.find((o) => o.grant === p.receipt.grant);
      await txn.delete(`g:${p.receipt.grant}`);
      return { ...m, used: m.used - (p.day === m.day ? 1 : 0) - (hold?.left ?? 0), open: m.open.filter((o) => o.grant !== p.receipt.grant) };
    });
  }

  /** An op re-timed out of its run (W1-W2, CC3): its entry, both its slots charged today, and its unit of the run's budget. */
  #withdrawOp(p: Pending, now: number) {
    return this.#withdraw(p, now, async (m, txn) => {
      const o = (await txn.get<OpState>(`o:${p.receipt.grant}`))!, run = (await txn.get<Grant>(`g:${o.run_grant}`))!;
      const hold = (m.op_open ?? []).find((h) => h.op === p.receipt.grant);
      await txn.delete(`o:${p.receipt.grant}`);
      await txn.put({ [`g:${o.run_grant}`]: { ...run, ops: Math.max(0, (run.ops ?? 0) - 1) } });
      return { ...m, op_used: (m.op_used ?? 0) - (p.day === m.day ? 1 : 0) - (hold?.left ?? 0), op_open: (m.op_open ?? []).filter((h) => h.op !== p.receipt.grant) };
    });
  }

  /**
   * A result re-timed past its op's 24 h (W2, CC3): the result goes, the op is `released` and its hold
   * removed, the result's slot comes off today's pool if charged today, counted once in `expired.op`.
   * The op itself was stored, so it keeps its unit of the run's budget.
   */
  #withdrawResult(p: Pending, now: number) {
    return this.#withdraw(p, now, async (m, txn) => {
      const { result: _, ...o } = (await txn.get<OpState>(`o:${p.receipt.grant}`))!;
      await txn.put({ [`o:${p.receipt.grant}`]: { ...o, state: "released" } satisfies OpState });
      const ex = m.expired ?? { tap: 0, op: 0 };
      return { ...m, op_used: (m.op_used ?? 0) - (p.day === m.day ? 1 : 0), op_open: (m.op_open ?? []).filter((h) => h.op !== p.receipt.grant), expired: { ...ex, op: ex.op + 1 } };
    });
  }

  /** The state entry holding a pending record's receipt, with `receipt` set: `g:` for tap stages, `o:` for op stages (BB3c). */
  async #receiptEntry(p: Pending, receipt: Receipt): Promise<[string, unknown]> {
    if (isOpStage(p.receipt.stage)) {
      const k = `o:${p.receipt.grant}`, o = (await this.storage.get<OpState>(k))!;
      return [k, p.receipt.stage === "op" ? { ...o, receipt } : { ...o, result: receipt }];
    }
    const k = `g:${p.receipt.grant}`, g = (await this.storage.get<Grant>(k))!;
    return [k, { ...g, stages: { ...g.stages, [receipt.stage]: receipt } }];
  }

  /** The pending record under a new name at the same number, with a random tag, signed again; its receipt follows. */
  async #retag(p: Pending): Promise<Pending> {
    const tag = [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, "0")).join("");
    const key = nameFor(p.receipt.seq, p.receipt.grant, p.receipt.stage, tag);
    // The tag is signed with the record, so the record verifies only under this one name.
    const stored = await this.#seal({ ...(JSON.parse(p.stored) as Envelope), tag });
    const moved: Pending = { ...p, key, stored, storedSha: await sha256(stored), receipt: { ...p.receipt, key } };
    const [k, v] = await this.#receiptEntry(p, moved.receipt);
    // The signed tag makes the envelope longer: the storage budget is charged the difference (Codex r2).
    const m = (await this.storage.get<Meta>("meta"))!;
    await this.storage.put({ pending: moved, meta: { ...m, bytes: m.bytes + len(stored) - len(p.stored) }, [k]: v });
    return moved;
  }

  /**
   * B2's checks of a pending record at the time it will carry (`at`: its recorded time, or now if it is
   * re-timed), made before it is written (W1): a run-open request always (CC4, even one queued by older
   * code); an op or op_result only when re-timed, since nothing else can change while it waits. Returns
   * the withdrawal's fixed words (W3) once it is withdrawn, or the parsed descriptor of a valid run-open request.
   */
  async #recheck(p: Pending, at: number, now: number, late: boolean): Promise<{ withdrawn?: string; descriptor?: Descriptor }> {
    const stage = p.receipt.stage;
    if (stage === "request") {
      const g = (await this.storage.get<Grant>(`g:${p.receipt.grant}`))!;
      if (g.job !== RUN_OPEN_JOB) return {};
      const checked = validate(bodyOf(p)), d = checked.ok ? runDescriptor(checked.record, at) : "not valid";
      if (typeof d !== "string") return { descriptor: d };
      await this.#withdrawRequest(p, now);
      return { withdrawn: d.startsWith("descriptor deadline") ? "the run's deadline passed before the run was recorded" : "the run-open request was not valid when recorded" };
    }
    if (!late || !isOpStage(stage)) return {};
    const o = (await this.storage.get<OpState>(`o:${p.receipt.grant}`))!;
    if (stage === "op_result") {
      if (at - o.at <= RESULT_MS) return {};
      await this.#withdrawResult(p, now);
      return { withdrawn: "this op's result is over 24 hours late" };
    }
    const op = validateOp(bodyOf(p));
    if (op.ok && op.record.stage === "op" && !this.#notCovered(op.record, await this.storage.get<Grant>(`g:${o.run_grant}`), at, 1)) return {};
    await this.#withdrawOp(p, now);
    return { withdrawn: "the run ended before this op was recorded" };
  }

  /** Stores the pending record, if any: stored (neither field), withdrawn with fixed words, or stuck with why. */
  async #finishPending(now: Date): Promise<Finished> {
    let p = await this.storage.get<Pending>("pending");
    if (!p) return {};
    let uploaded: Date | undefined;
    try {
      // Other names under this number are not looked at: the record is written beside them, and the
      // checker reports anything the recorder did not sign as foreign (card 6f681cc1). Halting here
      // instead let any bucket writer stop every record, and locked plants cannot be deleted.
      let there = await this.bucket.get(p.key);
      // Its exact name holding other bytes (planted ahead; names are predictable): it moves to a name
      // at the same number that no one could plant ahead. Ours from before a crash keeps its name.
      if (there && (await sha256(new Uint8Array(await there.arrayBuffer()))) !== p.storedSha) {
        p = await this.#retag(p);
        there = null;
      }
      // An approval not yet in the bucket is checked again before it is stored: one queued by a
      // recorder from before the passkey check (or before a new pin) must not slip through (Codex r1 #1).
      if (!there && p.receipt.stage === "approval" && (await this.#withdrawUnverified(p, now.getTime()))) return { withdrawn: "the approval did not pass the passkey check" };
      if (there) uploaded = there.uploaded; // ours, written before a crash: never withdrawn or re-timed (W3)
      else {
        const t = now.getTime(), late = t - Date.parse(p.receipt.recorded_at) > SKEW_MS / 2 || day(t) !== p.day;
        const re = await this.#recheck(p, late ? t : Date.parse(p.receipt.recorded_at), t, late);
        if (re.withdrawn) return { withdrawn: re.withdrawn };
        const op = isOpStage(p.receipt.stage);
        const g = op ? undefined : (await this.storage.get<Grant>(`g:${p.receipt.grant}`))!;
        // A later stage re-timed past its grant's 24 h is withdrawn, never stored (REFINE v7 AA2). Its
        // grant's opening time never moves for it: only an opening record moves its own window.
        if (g && late && p.receipt.stage !== "request" && t - g.opened > GRANT_TTL_MS) {
          await this.#withdrawLate(p, t);
          return { withdrawn: "this grant's request is over 24 hours old" };
        }
        if (late) {
          // Stored late (the bucket was down), or on a later UTC day however briefly: no receipt has
          // gone out, so it takes the time it is actually stored, and its receipt says the same.
          const receipt = { ...p.receipt, recorded_at: now.toISOString() };
          // A new time means a new signature: the old one covered the old time. A legacy unsigned
          // envelope is signed here too; either way the budget is charged the length change (Z5).
          const stored = await this.#seal({ ...(JSON.parse(p.stored) as Envelope), recorded_at: receipt.recorded_at });
          let m = settle((await this.storage.get<Meta>("meta"))!, t, keepOf(p));
          let charged = p.day;
          if (day(t) !== p.day) {
            // Stored on a later UTC day: it is charged to that day, in its own pool. Nothing else is
            // taken while a record is pending, so this is the day's first write, after the carried holds.
            if (p.pool === "op") {
              if ((m.op_used ?? 0) + 1 > OP_DAY_CAP) return { stuck: `today's ${OP_DAY_CAP} op slots are taken; the pending record waits` };
              m = { ...m, op_used: (m.op_used ?? 0) + 1 };
            } else {
              if (m.used + 1 > DAY_CAP) return { stuck: `today's ${DAY_CAP} record slots are taken; the pending record waits` };
              m = { ...m, used: m.used + 1 };
            }
            charged = m.day;
          }
          let entry: [string, unknown];
          if (g) {
            let next: Grant = { ...g, stages: { ...g.stages, [receipt.stage]: receipt }, ...(re.descriptor ? { descriptor: re.descriptor } : {}) };
            if (receipt.stage === "request") {
              // An opening record's window starts when it is stored (T11): the grant's `opened` and its
              // hold move together, so recorder and checker (which reads `recorded_at`) agree. A hold that
              // is somehow gone is made again in full, and counted in today's pool.
              next = { ...next, opened: t };
              const hold = m.open.find((o) => o.grant === receipt.grant);
              m = hold
                ? { ...m, open: m.open.map((o) => (o.grant === receipt.grant ? { ...o, opened: t } : o)) }
                : { ...m, used: m.used + STAGE_SLOTS - 1, open: [...m.open, { grant: receipt.grant, opened: t, left: STAGE_SLOTS - 1 }] };
            }
            entry = [`g:${receipt.grant}`, next];
          } else {
            // An op moves its own time and its result's hold with it (AA2); a result moves nothing of its op's.
            const [k, v] = await this.#receiptEntry(p, receipt);
            entry = [k, receipt.stage === "op" ? { ...(v as OpState), at: t } : v];
            if (receipt.stage === "op") {
              const hold = (m.op_open ?? []).find((h) => h.op === receipt.grant);
              m = hold
                ? { ...m, op_open: m.op_open!.map((h) => (h.op === receipt.grant ? { ...h, at: t } : h)) }
                : { ...m, op_used: (m.op_used ?? 0) + 1, op_open: [...(m.op_open ?? []), { op: receipt.grant, at: t, left: 1 }] };
            }
          }
          m = { ...m, bytes: m.bytes + len(stored) - len(p.stored) };
          p = { ...p, stored, storedSha: await sha256(stored), receipt, day: charged };
          await this.storage.put({ meta: peak(m), [entry[0]]: entry[1], pending: p });
        } else if ((JSON.parse(p.stored) as Envelope).v !== 2) {
          // Queued before this recorder signed records (card 6a04908f): signed now, before it is stored,
          // and the budget is charged the length change (Z5; before card 509a5d85 it was not).
          const stored = await this.#seal(JSON.parse(p.stored) as Envelope);
          const m = (await this.storage.get<Meta>("meta"))!;
          await this.storage.put({ meta: { ...m, bytes: m.bytes + len(stored) - len(p.stored) }, pending: (p = { ...p, stored, storedSha: await sha256(stored) }) });
        }
        // A valid run-open request queued by older code gets the descriptor its approval will need (CC4).
        if (!late && g && re.descriptor && !g.descriptor) await this.storage.put({ [`g:${p.receipt.grant}`]: { ...g, descriptor: re.descriptor, ops: g.ops ?? 0 } });
        uploaded = (await this.bucket.put(p.key, p.stored, { customMetadata: { sha256: p.storedSha }, httpMetadata: { contentType: "application/json" } }))?.uploaded;
      }
    } catch {
      return { stuck: "the records bucket did not take the write; it will be retried" };
    }
    await this.#stored(p, uploaded);
    return {};
  }

  /**
   * Removes `pending` once its record is in the bucket. A run-open request or approval whose object R2
   * stored more than SKEW_MS from its recorded time is kept (W3) but covers no op: the request's run is
   * marked `late` (DD1), the approval's `checked` is cleared (CC2), in the same transaction as the
   * removal, so the recorder agrees with the checker's X1 rule (records.ts checkStored). No upload time
   * known counts as late.
   */
  async #stored(p: Pending, uploaded: Date | undefined): Promise<void> {
    const k = `g:${p.receipt.grant}`, stage = p.receipt.stage;
    const run = (stage === "request" || stage === "approval") && (await this.storage.get<Grant>(k))?.job === RUN_OPEN_JOB;
    const off = !(uploaded instanceof Date) || !(Math.abs(uploaded.getTime() - Date.parse(p.receipt.recorded_at)) <= SKEW_MS);
    if (!run || !off) {
      await this.storage.delete("pending");
      return;
    }
    await this.storage.transaction(async (txn) => {
      const g = (await txn.get<Grant>(k))!;
      await txn.put({ [k]: stage === "request" ? { ...g, late: true } : { ...g, checked: false } });
      await txn.delete("pending");
    });
  }
}
