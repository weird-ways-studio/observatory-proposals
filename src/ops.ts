// Run operations (card 1a272a5c; refinement studio-os docs/specifications/trust-but-verify/
// REFINE-observatory-ops.md, v4 sections win). One place for the op format, the run-open descriptor and
// the coverage rules. Build A: only the hourly checker (src/runcheck.ts) uses this file, and the live
// recorder still refuses `op` and `op_result` (contract.ts `validate` is unchanged). Build B's recorder
// imports the same parser and rules, so both sides read a run one way.
import { GRANT, MAX_RECORD_BYTES, MAX_STORED_BYTES, ROOT, STAGE_SLOTS, type Stage } from "./contract.ts";
import { canonical } from "./recorder/passkey.ts";

/** The front desk's run-open job (4a-3 must use this name). Its request carries the descriptor. */
export const RUN_OPEN_JOB = "cf.run.open";
/** Jobs a run may hold and each one's exact param keys, mirroring front-desk vault RUN_ELIGIBLE and its
 * params fence (vault/src/runs.ts `outside`, @6bcc466). A zone param is a zone NAME, as the vault matches it. */
export const RUN_JOBS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  "cf.zone.read": ["zone"],
  "cf.dns.list": ["zone"],
  "cf.audit.read": ["since", "until"],
});
/** Why codes per outcome (X3), pinned to front-desk @6bcc466 and REFINE-phase4a2.md v3-v6. "done" takes none. */
export const RESULT_WHY: Readonly<Record<string, readonly string[]>> = Object.freeze({
  done: [],
  refused: ["unknown_run", "no_run_key", "card_not_in_run", "job_not_in_run", "params_outside_run", "budget_spent", "run_ended", "run_stopped", "run_finished", "run_changed", "cbox_key_changed", "op_replayed", "not_signed", "bad_signature"],
  failed: ["provider_refused", "provider_timeout", "storage_before_call", "release_not_saved", "release_uncertain"],
  // B2 (REFINE v6 Z8): the vault's release reasons "c-box key changed" and "changed" (front-desk vault/src/runs.ts:202
  // @6bcc466) as codes. Changed here, in the one list, so the checker and the recorder change together.
  not_returned: ["stopped", "finished", "ended", "cbox_key_changed", "run_changed"],
});
/**
 * The first record number whose run-open requests may cover ops (W5): records 1-3 hold approvals stored
 * before the passkey check. Set only by build B's PR, to the recorder's next number at merge (Ben merges
 * it). Undefined: no run covers anything, so any op is `op-uncovered`.
 */
export const OPS_FROM: number | undefined = undefined;
export const OP_DAY_CAP = 400; // the op pool's own slots a UTC day; taps keep contract DAY_CAP
export const RUN_BUDGET_MAX = 50;
export const RUN_MAX_MS = 24 * 3_600_000; // deadline at most this long after the run-open request
export const RESULT_MS = 24 * 3_600_000; // a result must be recorded within this of its op
export const RUN_CUTOFF_BYTES = 5 * 1024 ** 3; // ops stop being admitted past this (B); taps may use the full budget

export type OpStage = "op" | "op_result";
export type AnyStage = Stage | OpStage;
/** True for the two op stages, which have their own format and pool. */
export const isOpStage = (s: string): s is OpStage => s === "op" || s === "op_result";
// Op records get their own name pattern; the shared KEY stays unchanged, so recorder names do not change.
const ID = "[A-Za-z0-9][A-Za-z0-9_-]{7,63}";
export const OP_KEY = new RegExp(`^records/v1/(\\d{12})\\.(${ID})\\.(op|op_result)(?:\\.([0-9a-f]{16}))?\\.json$`);
const ANY_KEY = new RegExp(`^records/v1/(\\d{12})\\.(${ID})\\.(request|approval|verdict|result|op|op_result)(?:\\.([0-9a-f]{16}))?\\.json$`);
/** A stored name's parts, for grant records and op records alike; undefined for anything else. */
export function nameOf(name: string): { n: number; grant: string; stage: AnyStage; tag?: string } | undefined {
  const m = ANY_KEY.exec(name);
  return m ? { n: Number(m[1]), grant: m[2], stage: m[3] as AnyStage, ...(m[4] ? { tag: m[4] } : {}) } : undefined;
}
/** The stored name for an op record, as keyFor names grant records. */
export const opKeyFor = (seq: number, op: string, stage: OpStage, tag?: string) => `${ROOT}${String(seq).padStart(12, "0")}.${op}.${stage}${tag ? `.${tag}` : ""}.json`;

/** What Ben's run-open tap approves (V4): the vault's RunRecord fields, `budget` = budget.max. */
export interface Descriptor { run: string; cards: string[]; jobs: string[]; account: string; zones: { id: string; name: string }[]; template: number; deadline: number; budget: number }
export interface Op { v: 1; grant: string; stage: "op"; job: string; run_grant: string; run_request: string; run: string; card: string; template: number; params: Record<string, string> }
export interface OpResult { v: 1; grant: string; stage: "op_result"; job: string; run: string; op: string; outcome: string; why?: string; answer_sha256?: string }

const SHA = /^[0-9a-f]{64}$/, CARD = /^[0-9a-f]{8}$/, ACCOUNT = /^[0-9a-f]{32}$/;
const DNS = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const ISO_S = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/; // the vault's audit window format
const obj = (v: unknown): v is Record<string, unknown> => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const exactly = (o: Record<string, unknown>, keys: readonly string[]) => Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));
const int = (v: unknown, lo: number, hi = Number.MAX_SAFE_INTEGER): v is number => Number.isSafeInteger(v) && !Object.is(v, -0) && (v as number) >= lo && (v as number) <= hi;
const list = (v: unknown, lo: number, hi: number, each: (x: unknown) => boolean) => Array.isArray(v) && v.length >= lo && v.length <= hi && v.every(each);
const unique = (xs: unknown[]) => new Set(xs.map((x) => JSON.stringify(x))).size === xs.length;
const isJob = (j: unknown): j is string => typeof j === "string" && Object.hasOwn(RUN_JOBS, j);

/**
 * The descriptor from a run-open request's `params.descriptor`, the only source (V4). Refused (a fixed
 * reason) unless re-encoding gives the same text, the shape is exact, and deadline and budget are within
 * the caps from the request's own recorded time.
 */
export function parseDescriptor(text: unknown, requestAt: number): Descriptor | string {
  if (typeof text !== "string") return "no descriptor";
  let d: unknown;
  try {
    d = JSON.parse(text);
  } catch {
    return "descriptor is not JSON";
  }
  if (!obj(d) || canonical(d) !== text) return "descriptor is not canonical JSON";
  if (!exactly(d, ["account", "budget", "cards", "deadline", "jobs", "run", "template", "zones"])) return "descriptor has the wrong fields";
  if (typeof d.run !== "string" || !GRANT.test(d.run)) return "descriptor run id";
  if (!list(d.cards, 1, 20, (c) => typeof c === "string" && CARD.test(c)) || !unique(d.cards as unknown[])) return "descriptor cards";
  if (!list(d.jobs, 1, 10, isJob) || !unique(d.jobs as unknown[])) return "descriptor jobs";
  if (typeof d.account !== "string" || !ACCOUNT.test(d.account)) return "descriptor account";
  const zone = (z: unknown) => obj(z) && exactly(z, ["id", "name"]) && typeof z.id === "string" && ACCOUNT.test(z.id) && typeof z.name === "string" && DNS.test(z.name);
  const zones = d.zones as { id: string; name: string }[];
  if (!list(zones, 0, 50, zone) || !unique(zones.map((z) => z.id)) || !unique(zones.map((z) => z.name))) return "descriptor zones";
  if (!int(d.template, 1)) return "descriptor template";
  if (!int(d.deadline, requestAt + 1, requestAt + RUN_MAX_MS)) return "descriptor deadline is not within 24 hours of the run-open request";
  if (!int(d.budget, 1, RUN_BUDGET_MAX)) return `descriptor budget is not 1 to ${RUN_BUDGET_MAX}`;
  return d as unknown as Descriptor;
}

/** Checks an op or op_result body (W7, X3): exact fields, extra fields refused. Reasons are fixed words. */
export function validateOp(body: string): { ok: true; record: Op | OpResult } | { ok: false; why: string } {
  if (new TextEncoder().encode(body).length > MAX_RECORD_BYTES) return { ok: false, why: `over ${MAX_RECORD_BYTES} bytes` };
  let r: unknown;
  try {
    r = JSON.parse(body);
  } catch {
    return { ok: false, why: "not JSON" };
  }
  const no = (why: string) => ({ ok: false as const, why });
  if (!obj(r) || r.v !== 1 || typeof r.grant !== "string" || !GRANT.test(r.grant)) return no("no valid op id");
  if (!isJob(r.job)) return no("not a run job");
  if (typeof r.run !== "string" || !GRANT.test(r.run)) return no("no valid run id");
  if (r.stage === "op") {
    if (!exactly(r, ["v", "grant", "stage", "job", "run_grant", "run_request", "run", "card", "template", "params"])) return no("op has the wrong fields");
    if (typeof r.run_grant !== "string" || !GRANT.test(r.run_grant)) return no("no valid run grant");
    if (typeof r.run_request !== "string" || !SHA.test(r.run_request)) return no("no valid run request hash");
    if (typeof r.card !== "string" || !CARD.test(r.card)) return no("no valid card");
    if (!int(r.template, 1)) return no("no valid template");
    const p = r.params;
    if (!obj(p) || !exactly(p, RUN_JOBS[r.job])) return no("params are not the job's params");
    if (Object.hasOwn(p, "zone") && (typeof p.zone !== "string" || !DNS.test(p.zone))) return no("no valid zone name");
    if (Object.hasOwn(p, "since") && ![p.since, p.until].every((x) => typeof x === "string" && ISO_S.test(x))) return no("no valid audit window");
    return { ok: true, record: r as unknown as Op };
  }
  if (r.stage !== "op_result") return no("no valid stage");
  const keys = ["v", "grant", "stage", "job", "run", "op", "outcome", ...(r.outcome === "done" ? ["answer_sha256"] : ["why"])];
  if (typeof r.outcome !== "string" || !Object.hasOwn(RESULT_WHY, r.outcome)) return no("no valid outcome"); // a string, never coerced (Codex r1 #1)
  if (!exactly(r, keys)) return no("result has the wrong fields for its outcome");
  if (typeof r.op !== "string" || !SHA.test(r.op)) return no("no valid op hash");
  if (r.outcome === "done" ? typeof r.answer_sha256 !== "string" || !SHA.test(r.answer_sha256) : !RESULT_WHY[r.outcome as string].includes(r.why as string)) return no("no valid why or answer hash");
  return { ok: true, record: r as unknown as OpResult };
}

/** A run as the checker (and B's recorder) knows it: its run-open request, and whether Ben's approval passed. */
export interface RunSeen { seq: number; sha: string; descriptor: Descriptor | string; approved: boolean; ops: number }
/**
 * Why an op is not covered by Ben's passkey-approved run, or undefined when it is (V3, W5). `at` is the
 * op's recorded time; `run.ops` counts the unique ops already seen for the run, not this one.
 */
export function uncovered(op: Op, run: RunSeen, at: number, opsFrom = OPS_FROM): string | undefined {
  if (opsFrom === undefined) return "run operations are not switched on yet";
  if (run.seq < opsFrom) return "its run was opened before run operations were switched on";
  if (!run.approved) return "its run has no approval that passed the checks";
  if (typeof run.descriptor === "string") return `its run's ${run.descriptor}`;
  const d = run.descriptor;
  if (op.run_request !== run.sha) return "it names a different run-open request";
  if (op.run !== d.run) return "it names a different run id";
  if (!d.cards.includes(op.card)) return "its card is not in the run";
  if (!d.jobs.includes(op.job)) return "its job is not in the run";
  if (Object.hasOwn(op.params, "zone") && !d.zones.some((z) => z.name === op.params.zone)) return "its zone is not in the run";
  if (op.template !== d.template) return "its job template is not the run's";
  if (at >= d.deadline) return "it was recorded after the run's deadline";
  if (run.ops >= d.budget) return "the run's budget was already spent";
  return undefined;
}

/**
 * Pool use on a UTC day (W8, X4), shared with B's recorder status: records charged to each pool that day
 * plus every outstanding reservation, whatever day it was made. A tap grant opened within 24 h holds
 * (4 - its stages stored); an op stored within 24 h with no valid result holds 1.
 */
export function poolUse(now: number, charged: { tap: number; op: number }, taps: { opened: number; stored: number }[], ops: { at: number }[]) {
  const tapHeld = taps.filter((t) => now - t.opened <= RUN_MAX_MS).reduce((n, t) => n + Math.max(0, STAGE_SLOTS - t.stored), 0);
  const opHeld = ops.filter((o) => now - o.at <= RESULT_MS).length;
  return { tap: charged.tap + tapHeld, op: charged.op + opHeld, reserved_bytes: (tapHeld + opHeld) * MAX_STORED_BYTES };
}
