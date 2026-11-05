// B2 (card 8ff5110b): the recorder admits run ops. Section ids are REFINE-observatory-ops.md v13 BB1-BB10,
// v14 CC1-CC6, v15 DD1, v16 DD3 (later wins) on the earlier V/W/X/Z/AA/AB/AE sections; "row N" is the
// BB4 threat table. Every refusal here has a mutant in test/mutants.json whose `why` names the defect.
import { test } from "node:test";
import assert from "node:assert/strict";
import { DAY_CAP, MAX_STORED_BYTES, sha256, SKEW_MS, STAGE_SLOTS, STORE_BUDGET_BYTES } from "../src/contract.ts";
import { Ledger, OPS_ENABLED, REFUSALS, type Outcome } from "../src/recorder/ledger.ts";
import { OP_DAY_CAP, OPS_FROM, poolUse, RESULT_MS } from "../src/ops.ts";
import { DAY, desc, HOUR, iso, MIN, ms, openRun, opBody, resBody, RG, runAppr, runLedger, runReq, storeOp } from "./runs.ts";

type St = ReturnType<typeof runLedger>["st"];
type B = ReturnType<typeof runLedger>["b"];
interface Meta { seq: number; day: string; used: number; bytes: number; open: { grant: string; opened: number; left: number }[]; op_used?: number; op_open?: { op: string; at: number; left: number }[]; expired?: { tap: number; op: number }; op_peak?: number; op_peak_prev?: number }
interface Run { job: string; request: string; opened: number; stages: Record<string, { seq: number; key: string; recorded_at: string }>; descriptor?: object; checked?: boolean; late?: boolean; ops?: number }
interface OpSt { run_grant: string; sha: string; at: number; receipt: { seq: number; key: string; recorded_at: string }; result?: { seq: number }; state: string }

const A = ms("2026-11-05T10:00:00Z");
const at = (t: number) => () => new Date(t);
const meta = (st: St) => st.m.get("meta") as Meta;
const run = (st: St, g = RG) => st.m.get(`g:${g}`) as Run | undefined;
const opOf = (st: St, id: string) => st.m.get(`o:${id}`) as OpSt | undefined;
const hold = (st: St, id: string) => meta(st).op_open?.find((h) => h.op === id);
const len = (s: string) => new TextEncoder().encode(s).length;
const storedBytes = (b: B) => [...b.store.values()].reduce((n, v) => n + len(v.body), 0);
const why = (o: Outcome) => ("why" in o ? o.why : undefined);
const tap = (g: string) => JSON.stringify({ v: 1, grant: g, stage: "request", job: "test.echo" });
/** Every number, byte and pool count that a withdrawal must give back, for before/after comparisons. */
const totals = (st: St) => ({ seq: meta(st).seq, bytes: meta(st).bytes, used: meta(st).used, op_used: meta(st).op_used, ops: run(st)?.ops, op_open: meta(st).op_open?.length });

/** A run opened at A with an op stored at A + 10 min. */
async function withOp(opts: Parameters<typeof runLedger>[0] = { opsFrom: 1 }) {
  const w = runLedger(opts);
  const req = await openRun(w.l, A);
  const op = await storeOp(w.l, "op-0000000001", req, A + 10 * MIN);
  return { ...w, req, op };
}

// ---- BB2.1, rows 3-4: the run-open request ----

test("BB2.1/row 4: a run-open request is stored only with params exactly {descriptor}, valid at its own recorded time", async () => {
  const { l, st } = runLedger();
  for (const [body, want] of [
    [runReq(desc(A), RG, { params: { descriptor: desc(A), extra: "x" } }), "a run-open request's params must be exactly the descriptor"],
    [runReq(JSON.stringify(JSON.parse(desc(A)), null, 1)), "descriptor is not canonical JSON"],
    [runReq(desc(A, { deadline: A + DAY + 1 })), "descriptor deadline is not within 24 hours of the run-open request"],
    [runReq(desc(A, { budget: 51 })), "descriptor budget is not 1 to 50"],
  ] as const) assert.deepEqual(await l.accept(body, at(A)), { status: 400, why: want }, "an invalid run-open request was stored");
  assert.equal(meta(st), undefined, "a refused run-open request touched the ledger");
  await openRun(l, A, { approve: false });
  assert.deepEqual([typeof run(st)!.descriptor, run(st)!.ops], ["object", 0]);
  assert.equal((await l.status(at(A + MIN))).ops.runs_admitted, 1);
});

test("row 3: an approved ordinary grant (test.echo) is not a run: an op naming it is refused", async () => {
  const { l } = runLedger();
  const body = tap("echo-grant-01");
  await l.accept(body, at(A));
  await l.accept(JSON.stringify({ v: 1, grant: "echo-grant-01", stage: "approval", job: "test.echo", request: await sha256(body) }), at(A + MIN));
  const out = await l.accept(opBody("op-0000000001", await sha256(body), { run_grant: "echo-grant-01" }), at(A + 2 * MIN));
  assert.deepEqual(out, { status: 409, why: "it names no run-open request this recorder checked", reason: "uncovered" }, "an op was covered by a non-run grant");
});

// ---- BB2.2, rows 1, 6, 17: coverage ----

test("row 1 (Z7): an op is refused before its run's approval is stored, and the refusal is counted as uncovered", async () => {
  const { l } = runLedger();
  const req = await openRun(l, A, { approve: false });
  assert.deepEqual(await l.accept(opBody("op-0000000001", req), at(A + 2 * MIN)), { status: 409, why: "its run has no approval that passed the checks", reason: "uncovered" }, "an op was stored with no approval for its run");
  assert.equal((await l.status(at(A + 3 * MIN))).refused.uncovered, 1);
});

test("row 1/row 17: an approval this recorder did not mark checked (pre-B2 shape) covers no op", async () => {
  const { l, st } = runLedger();
  const req = await openRun(l, A);
  st.m.set(`g:${RG}`, { ...run(st)!, checked: undefined });
  assert.deepEqual(await l.accept(opBody("op-0000000001", req), at(A + 2 * MIN)), { status: 409, why: "its run has no approval that passed the checks", reason: "uncovered" }, "a run whose approval was never checked here covered an op");
});

test("row 1: OPS_FROM unset, or a run opened before it, covers nothing (one rule with the checker)", async () => {
  for (const [opts, want] of [[{ opsFrom: undefined }, "run operations are not switched on yet"], [{ opsFrom: 2 }, "its run was opened before run operations were switched on"]] as const) {
    const { l } = runLedger(opts);
    const req = await openRun(l, A);
    assert.deepEqual(await l.accept(opBody("op-0000000001", req), at(A + 2 * MIN)), { status: 409, why: want, reason: "uncovered" }, `op covered with opsFrom ${opts.opsFrom}`);
  }
});

test("row 6: an op outside its run (card, job, zone, template, deadline) is refused with uncovered()'s words", async () => {
  const { l, st } = runLedger();
  const req = await openRun(l, A);
  for (const [over, t, want] of [
    [{ card: "0000beef" }, A + MIN * 2, "its card is not in the run"],
    [{ params: { zone: "other.example" } }, A + MIN * 2, "its zone is not in the run"],
    [{ template: 2 }, A + MIN * 2, "its job template is not the run's"],
    [{ run_request: "f".repeat(64) }, A + MIN * 2, "it names a different run-open request"],
    [{}, A + 4 * HOUR, "it was recorded after the run's deadline"],
  ] as const) assert.deepEqual(await l.accept(opBody("op-0000000001", req, over), at(t)), { status: 409, why: want, reason: "uncovered" }, `an op outside its run was stored (${want})`);
  assert.equal(st.m.has("o:op-0000000001"), false);
});

// ---- BB2.2-3, rows 7, 9: admission, results, retries ----

test("BB2.2-3: a covered op takes 2 op slots and a run unit; its result redeems the hold; identical retries get the same receipt", async () => {
  const { l, st, b, op } = await withOp();
  const o = opOf(st, "op-0000000001")!;
  assert.deepEqual([meta(st).op_used, hold(st, "op-0000000001")?.left, run(st)!.ops, o.state, o.at], [2, 1, 1, "open", A + 10 * MIN]);
  assert.ok(b.store.has(o.receipt.key) && o.receipt.key.endsWith(".op-0000000001.op.json"));
  const res = resBody("op-0000000001", op);
  const r1 = await l.accept(res, at(A + 20 * MIN));
  assert.equal(r1.status, 201);
  assert.deepEqual([meta(st).op_used, hold(st, "op-0000000001")?.left, opOf(st, "op-0000000001")!.state, run(st)!.ops], [2, 0, "redeemed", 1], "a result charged its op pool again or kept the hold");
  assert.deepEqual(await l.accept(res, at(A + 30 * MIN)), { status: 200, receipt: (r1 as { receipt: object }).receipt });
  assert.deepEqual(await l.accept(opBody("op-0000000001", (await sha256(runReq(desc(A))))), at(A + 30 * MIN)), { status: 200, receipt: o.receipt });
  assert.deepEqual(await l.accept(opBody("op-0000000001", op), at(A + 30 * MIN)), { status: 409, why: "this op is already recorded with other content" });
  assert.deepEqual(await l.accept(resBody("op-0000000001", op, { answer_sha256: "d".repeat(64) }), at(A + 30 * MIN)), { status: 409, why: "this op already has a result with other content" });
  assert.equal(run(st)!.ops, 1, "an identical retry took a budget unit");
});

test("row 7: the run's budget counts unique ops; the last unit is taken, the next refused; a retry takes none", async () => {
  const { l, st } = runLedger();
  const req = await openRun(l, A, { descriptor: desc(A, { budget: 2 }) });
  await storeOp(l, "op-0000000001", req, A + 2 * MIN);
  await storeOp(l, "op-0000000002", req, A + 3 * MIN);
  assert.equal((await l.accept(opBody("op-0000000001", req), at(A + 4 * MIN))).status, 200);
  assert.deepEqual(await l.accept(opBody("op-0000000003", req), at(A + 5 * MIN)), { status: 409, why: "the run's budget was already spent", reason: "uncovered" }, "an op past the run's budget was stored");
  assert.equal(run(st)!.ops, 2);
});

test("row 9: a result is linked by op hash, run and job, once, within 24 h of its op (inclusive)", async () => {
  const { l, op } = await withOp();
  assert.deepEqual(await l.accept(resBody("op-0000000009", op), at(A + HOUR)), { status: 409, why: "no op is recorded under this id" });
  for (const over of [{ op: "f".repeat(64) }, { run: "run-00000002" }, { job: "cf.audit.read" }])
    assert.deepEqual(await l.accept(resBody("op-0000000001", op, over), at(A + HOUR)), { status: 409, why: "the result does not name its op's exact record, run and job" }, `a mismatched result was stored (${JSON.stringify(over)})`);
  assert.deepEqual(await l.accept(resBody("op-0000000001", op), at(A + 10 * MIN + RESULT_MS + 1)), { status: 410, why: "this op's result is over 24 hours late" }, "a result over 24 h after its op was stored");
  assert.equal((await l.accept(resBody("op-0000000001", op), at(A + 10 * MIN + RESULT_MS))).status, 201, "a result at exactly 24 h was refused");
});

test("row 13: an op id equal to a grant id lives apart from the grant", async () => {
  const { l, st } = runLedger();
  const req = await openRun(l, A);
  await l.accept(tap("shared-id-01"), at(A + 2 * MIN));
  const before = structuredClone(st.m.get("g:shared-id-01"));
  await storeOp(l, "shared-id-01", req, A + 3 * MIN);
  assert.deepEqual(st.m.get("g:shared-id-01"), before, "an op wrote over a grant with the same id");
  assert.equal(opOf(st, "shared-id-01")!.state, "open");
});

// ---- BB2.4, row 8: pools and the cutoff ----

test("row 8: a full op pool refuses the op (op_pool_full) and still takes Ben's tap", async () => {
  const { l, st, req } = await withOp();
  st.m.set("meta", { ...meta(st), op_used: OP_DAY_CAP - 1 });
  assert.deepEqual(await l.accept(opBody("op-0000000002", req), at(A + HOUR)), { status: 429, why: `today's ${OP_DAY_CAP} op slots are taken`, reason: "op_pool_full" }, "an op was stored past a full op pool");
  assert.equal((await l.accept(tap("echo-grant-02"), at(A + HOUR))).status, 201, "a full op pool blocked a tap");
  assert.equal((await l.status(at(A + HOUR))).refused.op_pool_full, 1);
});

test("row 8: past the cutoff (written + reserved + the op's two slots) ops stop; taps and results go on", async () => {
  const { l, st, b, op, req } = await withOp();
  const cut = meta(st).bytes + (STAGE_SLOTS - 2 + 1) * MAX_STORED_BYTES + 2 * MAX_STORED_BYTES - 1; // one byte short of room for a second op
  const l2 = new Ledger(st, b, STORE_BUDGET_BYTES, async () => undefined, { opsFrom: 1, cutoff: cut });
  assert.deepEqual(await l2.accept(opBody("op-0000000002", req), at(A + HOUR)), { status: 429, why: "run operations stop at the storage cutoff; the rest is kept for Ben's taps", reason: "run_cutoff" }, "an op was stored past the cutoff");
  assert.equal((await l2.accept(resBody("op-0000000001", op), at(A + HOUR))).status, 201, "the cutoff blocked a result");
  assert.equal((await l2.accept(tap("echo-grant-03"), at(A + HOUR))).status, 201, "the cutoff blocked a tap");
  void l;
});

test("DD3: a tap-only day at 397 refusing a request is an ordinary tap_pool_full", async () => {
  const { l, st } = runLedger();
  await l.accept(tap("echo-grant-04"), at(A));
  st.m.set("meta", { ...meta(st), used: DAY_CAP - 3 });
  const out = await l.accept(tap("echo-grant-05"), at(A + MIN));
  assert.equal(out.status, 429);
  assert.deepEqual([(await l.status(at(A + MIN))).refused.tap_pool_full, (await l.status(at(A + MIN))).refused.op_pool_full], [1, 0]);
});

// ---- BB2.5, row 16: the off switch ----

test("row 16 (V2): switched off, new ops are refused (403) while results, a pending result, holds and taps go on", async () => {
  const { st, b, l, op, req } = await withOp();
  const op2 = await storeOp(l, "op-0000000002", req, A + 11 * MIN);
  b.failNext(1);
  assert.equal((await l.accept(resBody("op-0000000002", op2), at(A + 12 * MIN))).status, 503);
  assert.equal(OPS_ENABLED, true, "B2 ships with run ops switched on");
  const off = new Ledger(st, b, STORE_BUDGET_BYTES, async () => undefined, { opsFrom: 1, opsEnabled: false });
  assert.deepEqual(await off.accept(opBody("op-0000000003", req), at(A + 13 * MIN)), { status: 403, why: "run operations are switched off", reason: "switched_off" }, "an op was stored with the switch off");
  assert.equal(opOf(st, "op-0000000002")!.result?.seq !== undefined && !st.m.has("pending"), true, "the pending result was not finished with the switch off");
  assert.equal((await off.accept(resBody("op-0000000001", op), at(A + 14 * MIN))).status, 201, "a result was refused with the switch off");
  assert.equal((await off.accept(tap("echo-grant-06"), at(A + 15 * MIN))).status, 201, "a tap was refused with the switch off");
  const s = await off.status(at(A + 16 * MIN));
  assert.deepEqual([s.ops.enabled, s.refused.switched_off], [false, 1]);
});

// ---- BB2.6, rows 2, 5, 11, 12, 10: the time rule and withdrawals ----

test("row 2 (BB3a): checked is set with the approval and cleared with it; a fault inside the withdrawal leaves both", async () => {
  let pass = true;
  const { l, st, b } = runLedger({ opsFrom: 1 }, async () => (pass ? undefined : "the passkey answer does not verify"));
  const body = runReq(desc(A));
  await l.accept(body, at(A));
  b.failNext(1);
  assert.equal((await l.accept(runAppr(await sha256(body)), at(A + MIN))).status, 503);
  assert.deepEqual([run(st)!.checked, Boolean(run(st)!.stages.approval)], [true, true], "checked was not written with the approval");
  pass = false;
  st.fault("meta");
  assert.equal((await l.accept(tap("echo-grant-07"), at(A + 2 * MIN))).status, 503);
  assert.deepEqual([run(st)!.checked, Boolean(run(st)!.stages.approval), st.m.has("pending")], [true, true, true], "a fault inside the withdrawal split checked from its approval");
  assert.equal((await l.accept(tap("echo-grant-07"), at(A + 3 * MIN))).status, 201);
  assert.deepEqual([run(st)!.checked, Boolean(run(st)!.stages.approval), st.m.has("pending")], [undefined, false, false], "a withdrawn approval left its run checked");
});

test("row 5 (BB3d): a run-open request re-timed past its deadline is withdrawn whole (410), no number gap", async () => {
  const { l, st, b } = runLedger();
  b.failNext(1);
  assert.equal((await l.accept(runReq(desc(A, { deadline: A + 30 * MIN })), at(A))).status, 503);
  const before = { seq: meta(st).seq, used: meta(st).used };
  assert.deepEqual(before, { seq: 1, used: STAGE_SLOTS });
  const out = await l.accept(tap("echo-grant-08"), at(A + 40 * MIN));
  assert.deepEqual([out.status, "receipt" in out && out.receipt.seq], [201, 1], "the next record did not take the withdrawn request's number");
  assert.deepEqual([run(st), meta(st).seq, meta(st).used, meta(st).open.length, meta(st).bytes === storedBytes(b)], [undefined, 1, STAGE_SLOTS, 1, true], "a withdrawn run-open request kept its number, slots, hold or grant");
});

test("row 5: the writer's retry of a withdrawn run-open request is refused (deadline) and stores nothing", async () => {
  const { l, st, b } = runLedger();
  b.failNext(1);
  await l.accept(runReq(desc(A, { deadline: A + 30 * MIN })), at(A));
  // The pending copy is withdrawn first in the retry's turn; the retry is then checked as new, at its own time.
  assert.deepEqual(await l.accept(runReq(desc(A, { deadline: A + 30 * MIN })), at(A + 40 * MIN)), { status: 400, why: "descriptor deadline is not within 24 hours of the run-open request" });
  assert.deepEqual([run(st), meta(st).seq, b.store.size], [undefined, 0, 0]);
});

test("AE1/row 5: a fault inside the run-open request withdrawal changes nothing; the next turn withdraws once", async () => {
  const { l, st, b } = runLedger();
  b.failNext(1);
  await l.accept(runReq(desc(A, { deadline: A + 30 * MIN })), at(A));
  const before = structuredClone([...st.m]);
  st.fault("meta");
  assert.equal((await l.accept(tap("echo-grant-10"), at(A + 40 * MIN))).status, 503);
  assert.deepEqual([...st.m].filter(([k]) => k !== "counters"), before.filter(([k]) => k !== "counters"), "a fault inside the request withdrawal changed state");
  assert.equal((await l.accept(tap("echo-grant-10"), at(A + 41 * MIN))).status, 201);
  assert.deepEqual([run(st), meta(st).seq, meta(st).used], [undefined, 1, STAGE_SLOTS]);
});

test("CC4: an inherited pending run-open request that is not valid is withdrawn even when not re-timed", async () => {
  const { l, st, b } = runLedger();
  b.failNext(1);
  await l.accept(runReq(desc(A)), at(A));
  // As queued by older code: params beyond the descriptor, and no descriptor kept on the grant.
  const p = st.m.get("pending") as { stored: string };
  const env = JSON.parse(p.stored);
  st.m.set("pending", { ...p, stored: JSON.stringify({ ...env, body: runReq(desc(A), RG, { params: { descriptor: desc(A), extra: "x" } }) }) });
  st.m.set(`g:${RG}`, { ...run(st)!, descriptor: undefined });
  assert.equal((await l.accept(tap("echo-grant-11"), at(A + 2 * MIN))).status, 201);
  assert.deepEqual([run(st), meta(st).seq], [undefined, 1], "an invalid inherited run-open request was stored");
});

test("CC4: an inherited run-open request already in the bucket is kept, but its approval and ops are refused", async () => {
  const { l, st } = runLedger();
  const req = await openRun(l, A, { approve: false });
  st.m.set(`g:${RG}`, { ...run(st)!, descriptor: undefined });
  assert.deepEqual(await l.accept(runAppr(req), at(A + MIN)), { status: 409, why: "the run-open request has no descriptor this recorder checked; open a new run" }, "an approval covered a request this recorder never parsed");
  assert.equal((await l.accept(opBody("op-0000000001", req), at(A + 2 * MIN))).status, 409);
});

test("CC4: a valid inherited pending run-open request gets its descriptor when stored, so its approval is taken", async () => {
  const { l, st, b } = runLedger();
  b.failNext(1);
  const body = runReq(desc(A));
  await l.accept(body, at(A));
  st.m.set(`g:${RG}`, { ...run(st)!, descriptor: undefined, ops: undefined });
  assert.equal((await l.accept(tap("echo-grant-12"), at(A + 2 * MIN))).status, 201);
  assert.equal(typeof run(st)!.descriptor, "object", "a valid inherited run-open request was stored without its descriptor");
  assert.equal((await l.accept(runAppr(await sha256(body)), at(A + 3 * MIN))).status, 201);
});

test("row 11 (W1, W3 words): an op pending until after its run's deadline is withdrawn whole; the run keeps its budget", async () => {
  const { l, st, b, req } = await withOp();
  const before = totals(st);
  b.failNext(1);
  assert.equal((await l.accept(opBody("op-0000000002", req), at(A + 4 * HOUR - MIN))).status, 503);
  assert.deepEqual([meta(st).op_used, run(st)!.ops], [4, 2]);
  // Recovered 11 min later (past the 5 min re-time line): re-checked at its new time, it is outside its run.
  assert.deepEqual(await l.accept(opBody("op-0000000002", req), at(A + 4 * HOUR + 10 * MIN)), { status: 409, why: "it was recorded after the run's deadline", reason: "uncovered" });
  assert.deepEqual(totals(st), before, "a withdrawn op kept its number, bytes, slots, hold or run unit");
  assert.equal(opOf(st, "op-0000000002"), undefined);
});

test("Z7: the last budget unit, re-timed inside its deadline, is stored (the re-check excludes the op itself)", async () => {
  const { l, st, b } = runLedger();
  const req = await openRun(l, A, { descriptor: desc(A, { budget: 1 }) });
  b.failNext(1);
  assert.equal((await l.accept(opBody("op-0000000001", req), at(A + 10 * MIN))).status, 503);
  assert.equal((await l.accept(tap("echo-grant-13"), at(A + 30 * MIN))).status, 201);
  const o = opOf(st, "op-0000000001")!;
  assert.deepEqual([o.receipt.recorded_at, o.at, hold(st, "op-0000000001")?.at, run(st)!.ops], [iso(A + 30 * MIN), A + 30 * MIN, A + 30 * MIN, 1], "a re-timed op was withdrawn as over budget, or did not move its time and hold");
});

test("W3: an op already written before a crash is kept past its deadline, and its retry gets the same receipt", async () => {
  const { l, st, b, req } = await withOp();
  st.fault("pending", 1); // past the admission put, the bucket write lands, then the turn dies before `pending` is removed
  await assert.rejects(l.accept(opBody("op-0000000002", req), at(A + 4 * HOUR - MIN)));
  const o = opOf(st, "op-0000000002")!;
  assert.ok(b.store.has(o.receipt.key));
  assert.equal((await l.accept(tap("echo-grant-14"), at(A + 5 * HOUR))).status, 201);
  assert.deepEqual(await l.accept(opBody("op-0000000002", req), at(A + 5 * HOUR)), { status: 200, receipt: o.receipt }, "an op already in the bucket was withdrawn or re-timed");
});

test("row 12 (CC3, AE1): a fault inside the op withdrawal changes nothing; the next turn withdraws once", async () => {
  const { l, st, b, req } = await withOp();
  b.failNext(1);
  await l.accept(opBody("op-0000000002", req), at(A + 4 * HOUR - MIN));
  const before = structuredClone([...st.m].filter(([k]) => k !== "counters"));
  st.fault("meta");
  assert.equal((await l.accept(tap("echo-grant-15"), at(A + 4 * HOUR + 10 * MIN))).status, 503);
  assert.deepEqual([...st.m].filter(([k]) => k !== "counters"), before, "a fault inside the op withdrawal changed state");
  assert.equal((await l.accept(tap("echo-grant-15"), at(A + 4 * HOUR + 11 * MIN))).status, 201);
  assert.deepEqual([opOf(st, "op-0000000002"), run(st)!.ops, meta(st).op_used], [undefined, 1, 2]);
});

test("row 10/12 (CC3): a result pending past its op's 24 h is withdrawn: released, hold gone, slot back, expired once; the op keeps its unit", async () => {
  const { l, st, b, op } = await withOp();
  b.failNext(1);
  const t0 = A + 10 * MIN + RESULT_MS - MIN;
  assert.equal((await l.accept(resBody("op-0000000001", op), at(t0))).status, 503);
  const before = { ...totals(st), expired: meta(st).expired!.op };
  st.fault("meta");
  assert.equal((await l.accept(tap("echo-grant-16"), at(t0 + 10 * MIN))).status, 503, "the withdrawal did not reach the fault");
  assert.equal(opOf(st, "op-0000000001")!.state, "redeemed", "a fault inside the result withdrawal changed state");
  assert.equal((await l.accept(tap("echo-grant-16"), at(t0 + 11 * MIN))).status, 201);
  const o = opOf(st, "op-0000000001")!;
  assert.deepEqual([o.state, o.result, hold(st, "op-0000000001"), run(st)!.ops, meta(st).expired!.op], ["released", undefined, undefined, 1, before.expired + 1], "the late result's withdrawal left the wrong op tuple");
  // A second try at the result is refused by state, and nothing is released twice.
  const again = { op_used: meta(st).op_used, expired: meta(st).expired!.op };
  assert.deepEqual(await l.accept(resBody("op-0000000001", op), at(t0 + 12 * MIN)), { status: 410, why: "this op's result is over 24 hours late" });
  assert.deepEqual({ op_used: meta(st).op_used, expired: meta(st).expired!.op }, again, "a hold was released twice");
});

test("row 10: a result after its op's hold expired is refused by time, and the pool is not released again", async () => {
  const { l, st, op } = await withOp();
  await l.status(at(A + 10 * MIN + RESULT_MS + 1));
  await l.accept(tap("echo-grant-17"), at(A + 10 * MIN + RESULT_MS + 2));
  const after = { op_used: meta(st).op_used, expired: meta(st).expired!.op };
  assert.equal(after.expired, 1);
  assert.deepEqual(await l.accept(resBody("op-0000000001", op), at(A + 10 * MIN + RESULT_MS + 3)), { status: 410, why: "this op's result is over 24 hours late" });
  assert.deepEqual({ op_used: meta(st).op_used, expired: meta(st).expired!.op }, after);
  assert.equal(opOf(st, "op-0000000001")!.state, "open", "expiry wrote op state (CC3: it is metadata-only)");
});

// ---- row 14: retag of op stages ----

for (const stage of ["op", "op_result"] as const) {
  test(`row 14 (BB3c): a pending ${stage} whose name is planted is retagged under o:, not g:`, async () => {
    const { l, st, b, op, req } = await withOp();
    b.failNext(1);
    const body = stage === "op" ? opBody("op-0000000002", req) : resBody("op-0000000001", op);
    await l.accept(body, at(A + HOUR));
    const p = st.m.get("pending") as { key: string };
    b.store.set(p.key, { body: "planted" });
    assert.equal((await l.accept(tap("echo-grant-18"), at(A + HOUR + MIN))).status, 201);
    const o = opOf(st, stage === "op" ? "op-0000000002" : "op-0000000001")!;
    const key = stage === "op" ? o.receipt.key : (o.result as unknown as { key: string }).key;
    assert.match(key, new RegExp(`\\.${stage}\\.[0-9a-f]{16}\\.json$`), "a retagged op record kept its planted name in o:");
    assert.ok(b.store.has(key));
    assert.equal(st.m.has("g:op-0000000002") || st.m.has("g:op-0000000001"), false, "retag wrote op state under g:");
  });
}

// ---- CC1: holds kept by pool and id ----

test("CC1: a tap grant and an op with the same id: the tap hold expires while the op is pending, and the reverse", async () => {
  // Tap X's hold runs out while op X is pending: the tap hold goes (counted once), the op hold stays.
  {
    const { l, st, b } = runLedger();
    await l.accept(tap("same-id-0001"), at(A - DAY + 15 * MIN)); // its hold runs out at A + 15 min
    const req = await openRun(l, A);
    b.failNext(1);
    await l.accept(opBody("same-id-0001", req), at(A + 10 * MIN));
    // Status settles with the pending record's hold kept (it writes nothing): the run request's 2 and nothing of tap X.
    const s = await l.status(at(A + 16 * MIN));
    assert.deepEqual([s.pools.tap.reserved_slots, s.pools.op.reserved_slots, s.expired.tap], [2, 1, 1], "a pending op kept a tap hold of the same id from expiring");
    assert.ok(st.m.has("pending"));
  }
  // Op X's hold runs out while tap request X is pending: the op hold goes, the tap hold stays.
  {
    const { l, st, b, req } = await withOp();
    await storeOp(l, "same-id-0002", req, A + 11 * MIN);
    b.failNext(1);
    await l.accept(tap("same-id-0002"), at(A + 11 * MIN + RESULT_MS - 1)); // the op's hold has 1 ms left
    const s = await l.status(at(A + 11 * MIN + RESULT_MS + 2));
    assert.deepEqual([s.pools.op.reserved_slots, s.pools.tap.reserved_slots, s.expired.op], [0, STAGE_SLOTS - 1, 2], "a pending tap request kept an op hold of the same id from expiring");
    assert.ok(st.m.has("pending"));
  }
});

// ---- CC2, DD1: late uploads of the run-open request or approval ----

test("CC2: an approval whose object lands 11 min after its recorded time is stored but covers no op; 9 min covers", async () => {
  for (const [late, covered] of [[11 * MIN, false], [9 * MIN, true]] as const) {
    const { l, st, b } = runLedger();
    const body = runReq(desc(A));
    await l.accept(body, at(A));
    b.lateBy(late);
    assert.equal((await l.accept(runAppr(await sha256(body)), at(A + MIN))).status, 201);
    b.lateBy(0);
    assert.equal(run(st)!.checked, covered, `an approval stored ${late / MIN} min late: wrong coverage`);
    const out = await l.accept(opBody("op-0000000001", await sha256(body)), at(A + 2 * MIN));
    assert.equal(out.status, covered ? 201 : 409, `op after an approval ${late / MIN} min late`);
    if (!covered) assert.equal(b.store.size, 2, "a refused op reached the bucket");
  }
});

test("DD1: a run-open request whose object lands 11 min late marks the run late: its approval is refused, no op stored", async () => {
  const { l, st, b } = runLedger();
  const body = runReq(desc(A));
  b.lateBy(11 * MIN);
  assert.equal((await l.accept(body, at(A))).status, 201);
  b.lateBy(0);
  assert.equal(run(st)!.late, true);
  assert.deepEqual(await l.accept(runAppr(await sha256(body)), at(A + MIN)), { status: 409, why: "the run-open request was stored late; open a new run" }, "an approval covered a run-open request stored late");
  assert.equal((await l.accept(opBody("op-0000000001", await sha256(body)), at(A + 2 * MIN))).status, 409);
  assert.equal(SKEW_MS, 10 * MIN, "the late-upload line is the checker's own SKEW_MS (records.ts checkStored)");
});

test("CC2: an approval written before a crash and found there late is judged by that object's upload time", async () => {
  const { l, st, b } = runLedger();
  const body = runReq(desc(A));
  await l.accept(body, at(A));
  b.lateBy(11 * MIN);
  st.fault("pending", 1);
  await assert.rejects(l.accept(runAppr(await sha256(body)), at(A + MIN)));
  b.lateBy(0);
  assert.equal(run(st)!.checked, true);
  assert.equal((await l.accept(tap("echo-grant-20"), at(A + 2 * MIN))).status, 201);
  assert.equal(run(st)!.checked, false, "an approval found in the bucket 11 min late still covered ops");
});

// ---- row 15: midnight; row 18: recorder vs checker; status ----

test("row 15/AA2: an op pending over midnight is charged to the new day's op pool, its time and hold move with it", async () => {
  const { l, st, b } = runLedger();
  const t0 = ms("2026-11-05T23:00:00Z");
  const req = await openRun(l, t0);
  b.failNext(1);
  await l.accept(opBody("op-0000000001", req), at(t0 + 59 * MIN));
  const t1 = ms("2026-11-06T00:01:00Z");
  assert.equal((await l.accept(tap("echo-grant-21"), at(t1))).status, 201);
  assert.deepEqual([meta(st).op_used, hold(st, "op-0000000001")?.at, opOf(st, "op-0000000001")!.at, meta(st).op_peak_prev], [2, t1, t1, 2], "a pending op over midnight was charged or timed wrong");
});

/** The checker's pool view from the bucket alone (A's poolUse inputs), ops included. */
function checker(b: B, now: number) {
  const env = [...b.store.values()].filter((v) => v.body.startsWith("{")).map((v) => JSON.parse(v.body) as { grant: string; stage: string; recorded_at: string });
  const today = new Date(now).toISOString().slice(0, 10), isOp = (s: string) => s === "op" || s === "op_result";
  const taps = new Map<string, { opened: number; stored: number }>(), ops = new Map<string, { at: number; done: boolean }>();
  for (const e of env) {
    if (isOp(e.stage)) {
      const o = ops.get(e.grant) ?? { at: NaN, done: false };
      if (e.stage === "op") o.at = ms(e.recorded_at);
      else o.done = true;
      ops.set(e.grant, o);
      continue;
    }
    const g = taps.get(e.grant) ?? { opened: NaN, stored: 0 };
    if (e.stage === "request") g.opened = ms(e.recorded_at);
    g.stored += 1;
    taps.set(e.grant, g);
  }
  const charged = { tap: env.filter((e) => !isOp(e.stage) && e.recorded_at.slice(0, 10) === today).length, op: env.filter((e) => isOp(e.stage) && e.recorded_at.slice(0, 10) === today).length };
  return poolUse(now, charged, [...taps.values()].filter((g) => !Number.isNaN(g.opened)), [...ops.values()].filter((o) => !o.done));
}

test("row 18/DD3 (AB1 with ops): recorder pools equal the checker's poolUse from records, per pool; a pending op is +2 slots", async () => {
  const { l, st, b, req, op } = await withOp();
  await l.accept(resBody("op-0000000001", op), at(A + 20 * MIN));
  await storeOp(l, "op-0000000002", req, A + 30 * MIN);
  let s = await l.status(at(A + HOUR)), c = checker(b, A + HOUR);
  assert.deepEqual([s.pools.tap.used, s.pools.op.used], [c.tap, c.op], "recorder pools differ from the checker's per-pool count (a cross-pool charge?)");
  b.failNext(1);
  await l.accept(opBody("op-0000000003", req), at(A + HOUR));
  s = await l.status(at(A + HOUR + MIN));
  c = checker(b, A + HOUR + MIN);
  // A pending op: the identity gives q (1, charged today) + its hold (1) - the checker's (0, it cannot see it).
  assert.deepEqual([s.pools.tap.used - c.tap, s.pools.op.used - c.op], [0, 2], "the pending identity does not hold per pool for an op");
  assert.equal(s.stored_bytes - storedBytes(b), len((st.m.get("pending") as { stored: string }).stored));
});

test("status (BB3f, CC5-CC6): every refusal word at 0, the switch, OPS_FROM, runs admitted, op pool and its peak", async () => {
  const { l } = await withOp();
  const s = await l.status(at(A + HOUR));
  for (const r of ["op_pool_full", "run_cutoff", "uncovered", "switched_off"]) assert.ok((REFUSALS as readonly string[]).includes(r) && s.refused[r] === 0, r);
  assert.deepEqual([s.ops, s.pools.op.used, s.pools.op.cap, s.op_peak, s.op_peak_prev], [{ enabled: true, from: 1, runs_admitted: 1 }, 2, OP_DAY_CAP, 2, 0]);
  const { l: fresh } = runLedger({});
  assert.equal((await fresh.status(at(A))).ops.from, OPS_FROM ?? null, "status does not show the reviewed OPS_FROM");
});
