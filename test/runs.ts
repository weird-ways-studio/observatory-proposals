// Shared by the B2 recorder tests (card 8ff5110b): a run opened through the real ledger, and op / op_result
// bodies in the wire format of src/ops.ts (REFINE-observatory-ops.md v3 W7, v4 X3).
import assert from "node:assert/strict";
import { sha256, STORE_BUDGET_BYTES } from "../src/contract.ts";
import { canonical } from "../src/recorder/passkey.ts";
import { Ledger, type OpsOptions } from "../src/recorder/ledger.ts";
import { bucket, storage } from "./store.ts";

export const RG = "runopen-0001", RUN = "run-00000001", CARD = "1a272a5c";
export const ACCOUNT = "a".repeat(32), ZONE = { id: "b".repeat(32), name: "example.com" };
export const MIN = 60_000, HOUR = 60 * MIN, DAY = 24 * HOUR;
export const T = (iso: string) => () => new Date(iso);
export const ms = (iso: string) => Date.parse(iso);
export const iso = (t: number) => new Date(t).toISOString();

/** A descriptor (V4) for a run opened at `at`: deadline 4 h on, budget 50, unless overridden. */
export const desc = (at: number, over: object = {}) => canonical({ run: RUN, cards: [CARD], jobs: ["cf.dns.list", "cf.audit.read"], account: ACCOUNT, zones: [ZONE], template: 1, deadline: at + 4 * HOUR, budget: 50, ...over });
export const runReq = (descriptor: string, grant = RG, over: object = {}) => JSON.stringify({ v: 1, grant, stage: "request", job: "cf.run.open", params: { descriptor }, ...over });
export const runAppr = (request: string, grant = RG) => JSON.stringify({ v: 1, grant, stage: "approval", job: "cf.run.open", request });
export const opBody = (id: string, runRequest: string, over: object = {}) => JSON.stringify({ v: 1, grant: id, stage: "op", job: "cf.dns.list", run_grant: RG, run_request: runRequest, run: RUN, card: CARD, template: 1, params: { zone: ZONE.name }, ...over });
export const resBody = (id: string, opSha: string, over: object = {}) => JSON.stringify({ v: 1, grant: id, stage: "op_result", job: "cf.dns.list", run: RUN, op: opSha, outcome: "done", answer_sha256: "c".repeat(64), ...over });

/** A ledger over in-memory storage and bucket; run ops on from record 1 unless told otherwise; passkey check passes. */
export function runLedger(ops: OpsOptions = { opsFrom: 1 }, approvals: (r: unknown, h?: string) => Promise<string | undefined> = async () => undefined, budget = STORE_BUDGET_BYTES) {
  const st = storage(), b = bucket();
  return { st, b, l: new Ledger(st, b, budget, approvals, ops) };
}

/** A run-open request at `at` and (unless `approve` is false) its approval a minute later; returns the request's hash. */
export async function openRun(l: Ledger, at: number, { grant = RG, descriptor = desc(at), approve = true } = {}) {
  const body = runReq(descriptor, grant);
  assert.equal((await l.accept(body, () => new Date(at))).status, 201, "run-open request not stored");
  const sha = await sha256(body);
  if (approve) assert.equal((await l.accept(runAppr(sha, grant), () => new Date(at + MIN))).status, 201, "run-open approval not stored");
  return sha;
}

/** An op stored at `at` under run `req`; returns its hash, which its result names. */
export async function storeOp(l: Ledger, id: string, req: string, at: number, over: object = {}) {
  const body = opBody(id, req, over);
  const out = await l.accept(body, () => new Date(at));
  assert.equal(out.status, 201, `op not stored: ${JSON.stringify(out)}`);
  return sha256(body);
}
