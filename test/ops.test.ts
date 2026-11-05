// Card 1a272a5c build A: the checker reads run operations. Each test names its row in the threat table
// (studio-os docs/specifications/trust-but-verify/OPS-CHECKER-THREATS-1a272a5c.md).
import { test } from "node:test";
import assert from "node:assert/strict";
import { b64, keyFor, MAX_STORED_BYTES, sealed, sha256, STORE_BUDGET_BYTES, type Envelope, type Stage } from "../src/contract.ts";
import { canonical } from "../src/recorder/passkey.ts";
import { Ledger, type Storage } from "../src/recorder/ledger.ts";
import { storage } from "./store.ts";
import { OP_DAY_CAP, opKeyFor, OPS_FROM, parseDescriptor, poolUse, RUN_CUTOFF_BYTES, validateOp, type OpStage } from "../src/ops.ts";
import { capacityFindings, loadOps, onApproval, onRequest } from "../src/runcheck.ts";
import { MAX_OPEN, runRecords, STATE_KEY, type Pin, type RecordsEnv } from "../src/records.ts";

const NOW = Date.parse("2026-11-05T12:00:00.000Z");
const MIN = 60_000, HOUR = 60 * MIN, DAY = 24 * HOUR;
const RG = "runopen-0001", RUN = "run-00000001", OP = "op-0000000001", CARD = "1a272a5c";
const ACCOUNT = "a".repeat(32), ZONE = { id: "b".repeat(32), name: "example.com" };

/** An R2 bucket in memory: list (prefix, startAfter, cursor, delimiter), get, put. */
function bucket() {
  const store = new Map<string, { body: string; uploaded: Date }>();
  return {
    store,
    async list(o: { prefix?: string; delimiter?: string; cursor?: string; startAfter?: string; limit?: number }) {
      const prefix = o.prefix ?? "", start = Number(o.cursor ?? 0), limit = o.limit ?? 1000, prefixes = new Set<string>(), objects: R2Object[] = [];
      for (const k of [...store.keys()].sort().filter((x) => x.startsWith(prefix) && (!o.startAfter || x > o.startAfter))) {
        const rest = k.slice(prefix.length), cut = o.delimiter ? rest.indexOf(o.delimiter) : -1;
        if (cut >= 0) prefixes.add(prefix + rest.slice(0, cut + 1));
        else objects.push({ key: k, size: store.get(k)!.body.length, uploaded: store.get(k)!.uploaded } as R2Object);
      }
      const page = objects.slice(start, start + limit), more = start + limit < objects.length;
      return { objects: page, delimitedPrefixes: [...prefixes], truncated: more, cursor: more ? String(start + limit) : undefined } as R2Objects;
    },
    async get(k: string) { const v = store.get(k); return v ? ({ text: async () => v.body } as R2ObjectBody) : null; },
    async put(k: string, b: string) { store.set(k, { body: b, uploaded: new Date(NOW) }); return {} as R2Object; },
  };
}

/** Records signed the way the recorder signs them, at chosen times: B's recorder does not exist yet. */
async function world() {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const pin: Pin = { key: b64((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer), from: 1 };
  const b = bucket(), copy = bucket();
  let seq = 0;
  const put = async (grant: string, stage: Stage | OpStage, rec: object, at: number, late = 0) => {
    const body = JSON.stringify({ v: 1, grant, stage, ...rec }), sha = await sha256(body), n = ++seq;
    const e: Envelope = { v: 2, seq: n, grant, stage: stage as Stage, recorded_at: new Date(at).toISOString(), sha256: sha, body };
    const sig = b64(await crypto.subtle.sign("Ed25519", pair.privateKey, sealed(e)));
    const name = stage === "op" || stage === "op_result" ? opKeyFor(n, grant, stage) : keyFor(n, grant, stage);
    b.store.set(name, { body: JSON.stringify({ ...e, sig }), uploaded: new Date(at + late) });
    return { sha, seq: n, body };
  };
  const env = { RECORDS: b, COPY: copy } as unknown as RecordsEnv;
  // `opsFrom` null: OPS_FROM unset (a default parameter would swallow undefined).
  const run = (t: number, opsFrom: number | null = 1) => runRecords(env, async () => new Response("", { status: 500 }), new Date(t), pin, opsFrom);
  const incidents = () => (JSON.parse(copy.store.get(STATE_KEY)!.body).incidents as { id: string; text: string }[]);
  const ids = () => incidents().map((i) => i.id);
  return { b, copy, put, run, ids, incidents, skip: () => ++seq };
}

const desc = (at: number, over: object = {}) => canonical({ run: RUN, cards: [CARD], jobs: ["cf.dns.list", "cf.audit.read"], account: ACCOUNT, zones: [ZONE], template: 1, deadline: at + 4 * HOUR, budget: 50, ...over });
type W = Awaited<ReturnType<typeof world>>;
/** A run-open request and (unless told not to) its approval. Returns the request's hash. */
async function openRun(w: W, at: number, { approve = true, descriptor = desc(at), job = "cf.run.open", grant = RG, approval = {} as object } = {}) {
  const req = await w.put(grant, "request", { job, params: { descriptor }, requester: "agent", expires_at: at + HOUR }, at);
  if (approve) await w.put(grant, "approval", { job, request: req.sha, ...approval }, at + MIN);
  return req.sha;
}
const opRec = (runRequest: string, over: object = {}) => ({ job: "cf.dns.list", run_grant: RG, run_request: runRequest, run: RUN, card: CARD, template: 1, params: { zone: ZONE.name }, ...over });
const doneRec = (opSha: string, over: object = {}) => ({ job: "cf.dns.list", run: RUN, op: opSha, outcome: "done", answer_sha256: "c".repeat(64), ...over });
const has = (ids: string[], kind: string) => ids.filter((i) => i.startsWith(kind));
// An incident's text, failing as an assertion (not a TypeError) when the incident is missing (card 0d001fc3).
const textOf = (w: W, pick: (id: string) => boolean, what: string) => {
  const i = w.incidents().find((x) => pick(x.id));
  assert.ok(i, `${what}: no such incident`);
  return i.text;
};

// ---- the format, on its own

test("row 3/4: the descriptor reads one way only: canonical, exact shape, deadline within 24 h, budget 1..50", () => {
  const t = NOW;
  assert.equal(typeof parseDescriptor(desc(t), t), "object");
  assert.equal(parseDescriptor(JSON.stringify(JSON.parse(desc(t)), null, 1), t), "descriptor is not canonical JSON", "a re-encoded descriptor is accepted");
  assert.equal(parseDescriptor(JSON.stringify({ zones: [], ...JSON.parse(desc(t)) }), t), "descriptor is not canonical JSON"); // key order
  assert.equal(parseDescriptor(desc(t, { extra: 1 }), t), "descriptor has the wrong fields", "a descriptor with an extra field is accepted");
  assert.match(String(parseDescriptor(desc(t, { deadline: t + 25 * HOUR }), t)), /deadline/, "a deadline past 24 h was accepted");
  assert.match(String(parseDescriptor(desc(t, { deadline: t }), t)), /deadline/);
  assert.match(String(parseDescriptor(desc(t, { budget: 51 }), t)), /budget/, "a budget over 50 was accepted");
  assert.match(String(parseDescriptor(desc(t, { budget: 0 }), t)), /budget/);
  assert.equal(parseDescriptor(desc(t, { jobs: ["cf.token.canary"] }), t), "descriptor jobs");
  assert.equal(parseDescriptor(desc(t, { zones: [ZONE, { ...ZONE, id: "d".repeat(32) }] }), t), "descriptor zones"); // two zones, one name
  assert.equal(parseDescriptor(desc(t, { cards: [CARD, CARD] }), t), "descriptor cards");
  assert.equal(parseDescriptor(desc(t, { template: 1.5 }), t), "descriptor template");
});

test("W7/X3: op and op_result take exact fields; result codes are pinned per outcome", () => {
  const op = (o: object) => validateOp(JSON.stringify({ v: 1, grant: OP, stage: "op", ...opRec("e".repeat(64)), ...o }));
  const res = (o: object) => validateOp(JSON.stringify({ v: 1, grant: OP, stage: "op_result", ...doneRec("e".repeat(64)), ...o }));
  assert.equal(op({}).ok, true);
  assert.equal(op({ extra: 1 }).ok, false, "an op with an extra field was accepted");
  assert.equal(op({ params: { zone: ZONE.name, account: ACCOUNT } }).ok, false);
  assert.equal(op({ job: "cf.audit.read", params: { since: "2026-11-01T00:00:00Z", until: "2026-11-02T00:00:00Z" } }).ok, true);
  assert.equal(op({ job: "cf.audit.read", params: { since: "yesterday", until: "2026-11-02T00:00:00Z" } }).ok, false);
  assert.equal(op({ job: "cf.token.canary" }).ok, false);
  assert.equal(res({}).ok, true);
  assert.equal(res({ answer_sha256: undefined }).ok, false); // done needs the answer hash
  assert.equal(res({ why: "stopped" }).ok, false); // and no why
  assert.equal(validateOp(JSON.stringify({ v: 1, grant: OP, stage: "op_result", job: "cf.dns.list", run: RUN, op: "e".repeat(64), outcome: "refused", why: "budget_spent" })).ok, true);
  assert.equal(validateOp(JSON.stringify({ v: 1, grant: OP, stage: "op_result", job: "cf.dns.list", run: RUN, op: "e".repeat(64), outcome: "refused", why: "provider_timeout" })).ok, false, "an op_result why code not pinned to its outcome was accepted");
  assert.equal(validateOp(JSON.stringify({ v: 1, grant: OP, stage: "op_result", job: "cf.dns.list", run: RUN, op: "e".repeat(64), outcome: "released", why: "stopped" })).ok, false);
  // Codex r1 #1: the outcome is a string, never coerced: ["refused"] is not "refused".
  for (const outcome of [["refused"], { toString: null }, 1, null]) assert.equal(validateOp(JSON.stringify({ v: 1, grant: OP, stage: "op_result", job: "cf.dns.list", run: RUN, op: "e".repeat(64), outcome, why: "budget_spent" })).ok, false, JSON.stringify(outcome));
});

test("Z8 (B2): not_returned takes cbox_key_changed and run_changed, and each such result clears its op for the checker", async () => {
  for (const why of ["cbox_key_changed", "run_changed"]) {
    assert.equal(validateOp(JSON.stringify({ v: 1, grant: OP, stage: "op_result", job: "cf.dns.list", run: RUN, op: "e".repeat(64), outcome: "not_returned", why })).ok, true, `not_returned/${why} refused`);
    const w = await world();
    const req = await openRun(w, NOW - 3 * HOUR);
    const op = await w.put(OP, "op", opRec(req), NOW - 2 * HOUR);
    await w.put(OP, "op_result", { job: "cf.dns.list", run: RUN, op: op.sha, outcome: "not_returned", why }, NOW - 2 * HOUR + MIN);
    await w.run(NOW + DAY);
    assert.deepEqual(has(w.ids(), "op-"), [], `the checker did not take a not_returned/${why} result`);
  }
});

test("row 19 (V1, V9a), since B2 (card 8ff5110b): the recorder reads op bodies with validateOp, so a bad op is refused 400 with its words", async () => {
  const l = new Ledger(storage(), bucket() as never, STORE_BUDGET_BYTES, async () => undefined, { opsFrom: 1 });
  assert.deepEqual(await l.accept(JSON.stringify({ v: 1, grant: OP, stage: "op", ...opRec("e".repeat(64)), extra: 1 })), { status: 400, why: "op has the wrong fields" });
  assert.deepEqual(await l.accept(JSON.stringify({ v: 1, grant: OP, stage: "op_result", ...doneRec("e".repeat(64)), outcome: "released" })), { status: 400, why: "no valid outcome" });
});

// ---- the chain, through the hourly run

test("a covered op and its result: no op findings, and the run's measures count them", async () => {
  const w = await world();
  const req = await openRun(w, NOW - 3 * HOUR);
  const op = await w.put(OP, "op", opRec(req), NOW - 2 * HOUR);
  await w.put(OP, "op_result", doneRec(op.sha), NOW - 2 * HOUR + MIN);
  const r = await w.run(NOW);
  assert.equal(r.records, "ran");
  assert.deepEqual(has(w.ids(), "op-"), []);
  assert.equal(r.ops.results, 1);
  assert.deepEqual(r.ops.ops_per_run, [{ ops: 1, length_ms: 0 }]);
});

test("rows 1, 8: with OPS_FROM unset, or a run opened before it, or no approval, nothing is covered", async () => {
  for (const [opsFrom, approve, why] of [[null, true, "not switched on"], [5, true, "before run operations"], [1, false, "no approval"]] as const) {
    const w = await world();
    const req = await openRun(w, NOW - 3 * HOUR, { approve });
    await w.put(OP, "op", opRec(req), NOW - 2 * HOUR);
    await w.run(NOW, opsFrom);
    const f = w.incidents().find((i) => i.id === `op-uncovered:${OP}`);
    assert.match(f?.text ?? "", new RegExp(why), `coverage case opsFrom=${opsFrom} approve=${approve}`);
  }
});

test("row 9 (V7.4): a mismatched approval never counts: not for a run, and not for a tap grant's result (fails on the old checkOrder)", async () => {
  const w = await world();
  const req = await openRun(w, NOW - 3 * HOUR, { approve: false });
  await w.put(RG, "approval", { job: "cf.run.open", request: "f".repeat(64) }, NOW - 3 * HOUR + MIN);
  await w.put(OP, "op", opRec(req), NOW - 2 * HOUR);
  // A tap grant whose only approval names another request, then its result.
  const tap = await w.put("grant-0001", "request", { job: "cf.token.canary" }, NOW - 2 * HOUR);
  await w.put("grant-0001", "approval", { job: "cf.token.canary", request: "f".repeat(64) }, NOW - 2 * HOUR + MIN);
  await w.put("grant-0001", "result", { job: "cf.token.canary", request: tap.sha }, NOW - 2 * HOUR + 2 * MIN);
  // An approval naming the run's own request hash but another job: only the order check refuses it.
  const r2 = await openRun(w, NOW - 2 * HOUR, { approve: false, grant: "runopen-0002" });
  await w.put("runopen-0002", "approval", { job: "cf.token.canary", request: r2 }, NOW - 2 * HOUR + MIN);
  await w.put("op-0000000002", "op", opRec(r2, { run_grant: "runopen-0002" }), NOW - 2 * HOUR + 2 * MIN);
  await w.run(NOW);
  const ids = w.ids();
  assert.ok(ids.includes(`mismatch:${RG}`) && ids.includes("mismatch:grant-0001") && ids.includes("mismatch:runopen-0002"));
  assert.match(textOf(w, (id) => id === "op-uncovered:op-0000000002", "op 2 uncovered"), /no approval/);
  assert.match(textOf(w, (id) => id === `op-uncovered:${OP}`, "op 1 uncovered"), /no approval/);
  assert.ok(ids.includes("unapproved:grant-0001"), "the result is unapproved: the mismatched approval did not count");
});

test("row 1: onApproval marks a run approved only by an approval naming the run's own request", () => {
  // Defence in depth: records.ts's order check already refuses such an approval (row 9), so only a direct call
  // shows this check works (card 0d001fc3: A's mutant "approval not bound to the run's request" survived).
  const s = loadOps(undefined);
  onRequest(s, RG, 1, "a".repeat(64), "cf.run.open", { params: { descriptor: desc(NOW) } }, NOW);
  onApproval(s, RG, "b".repeat(64));
  assert.equal(s.runs[RG].approved, false, "an approval naming another request does not approve the run");
  onApproval(s, RG, "a".repeat(64));
  assert.equal(s.runs[RG].approved, true, "the run's own approval does");
});

test("rows 2, 3: an ordinary grant, or a run-open request carrying more than the descriptor, covers nothing; an unknown run is unlinked", async () => {
  const w = await world();
  const tap = await w.put("grant-0002", "request", { job: "cf.token.canary", params: { descriptor: desc(NOW - 3 * HOUR) } }, NOW - 3 * HOUR);
  await w.put("grant-0002", "approval", { job: "cf.token.canary", request: tap.sha }, NOW - 3 * HOUR + MIN);
  await w.put("op-tapgrant1", "op", opRec(tap.sha, { run_grant: "grant-0002" }), NOW - 2 * HOUR);
  const wide = await w.put("runopen-0002", "request", { job: "cf.run.open", params: { descriptor: desc(NOW - 3 * HOUR), zone: "x.com" } }, NOW - 3 * HOUR);
  await w.put("runopen-0002", "approval", { job: "cf.run.open", request: wide.sha }, NOW - 3 * HOUR + MIN);
  await w.put("op-wideparam", "op", opRec(wide.sha, { run_grant: "runopen-0002" }), NOW - 2 * HOUR);
  await w.put("op-nowhere01", "op", opRec("e".repeat(64), { run_grant: "runopen-9999" }), NOW - 2 * HOUR);
  await w.run(NOW);
  const text = (id: string) => w.incidents().find((i) => i.id === id)?.text ?? "";
  assert.match(text("op-uncovered:op-tapgrant1"), /not a run-open request/, "a tap grant opened a run");
  assert.match(text("op-uncovered:op-wideparam"), /more than the descriptor/, "params beyond the descriptor were covered");
  assert.match(text("op-unlinked:op-nowhere01"), /no run-open request/);
});

test("rows 5, 7: every field outside the descriptor is its own reason; so is an op after the deadline", async () => {
  const cases: [object, number, RegExp][] = [
    [{ card: "00000000" }, 0, /card/], [{ job: "cf.zone.read" }, 0, /job/], [{ params: { zone: "other.com" } }, 0, /zone/],
    [{ template: 2 }, 0, /template/], [{ run: "run-00000002" }, 0, /run id/], [{ run_request: "e".repeat(64) }, 0, /different run-open request/],
    [{}, 4 * HOUR, /deadline/],
  ];
  for (const [over, after, why] of cases) {
    const w = await world();
    const t = NOW - 5 * HOUR, req = await openRun(w, t);
    await w.put(OP, "op", opRec(req, over), t + 2 * MIN + after);
    await w.run(NOW);
    assert.match(w.incidents().find((i) => i.id === `op-uncovered:${OP}`)?.text ?? "", why, `uncovered case ${JSON.stringify(over)}`);
  }
});

test("row 6: budget counts unique ops; the one past it is uncovered; a second record for one op is a duplicate, not a unit", async () => {
  const w = await world();
  const t = NOW - 3 * HOUR, req = await openRun(w, t, { descriptor: desc(t, { budget: 2 }) });
  for (const [i, id] of ["op-0000000001", "op-0000000001", "op-0000000002", "op-0000000003"].entries()) await w.put(id, "op", opRec(req), t + (2 + i) * MIN);
  await w.run(NOW);
  const ids = w.ids();
  assert.ok(ids.includes("duplicate:o:op-0000000001:op"));
  assert.deepEqual(has(ids, "op-uncovered"), ["op-uncovered:op-0000000003"], "the op past the run budget is not uncovered");
});

test("row 1 (commit security review): a reused run-open grant id voids the run; its new approval never approves the old descriptor", async () => {
  const w = await world();
  const t = NOW - 3 * HOUR, req = await openRun(w, t, { approve: false });
  // The grant map lets the first request go (MAX_OPEN newer grants), so the reused id passes the order check.
  const open = Object.fromEntries(Array.from({ length: MAX_OPEN }, (_, i) => [`seeded-${String(i).padStart(6, "0")}`, { job: "cf.token.canary", req: "e".repeat(64), at: NOW - HOUR, stages: ["request"] }]));
  await w.run(t + MIN);
  const st = JSON.parse(w.copy.store.get(STATE_KEY)!.body);
  await w.copy.put(STATE_KEY, JSON.stringify({ ...st, open: { ...st.open, ...open } }));
  await w.run(t + 2 * MIN);
  // Identical request bytes again (same hash, so binding the approval to the hash alone would pass), then a different one.
  await openRun(w, t);
  const again = await openRun(w, t + 3 * MIN, { descriptor: desc(t, { budget: 1 }) });
  await w.put(OP, "op", opRec(req), t + 5 * MIN);
  await w.put("op-0000000002", "op", opRec(again), t + 6 * MIN);
  await w.run(NOW);
  assert.ok(w.ids().includes(`op-uncovered:${OP}`) && w.ids().includes("op-uncovered:op-0000000002"), "a reused run-open grant id does not void the run");
});

test("row 10: an op id equal to a grant id: each is checked in its own map", async () => {
  const w = await world();
  const t = NOW - 3 * HOUR, req = await openRun(w, t);
  const g = await w.put("shared-id-01", "request", { job: "cf.token.canary" }, t + 2 * MIN);
  await w.put("shared-id-01", "approval", { job: "cf.token.canary", request: g.sha }, t + 3 * MIN);
  const op = await w.put("shared-id-01", "op", opRec(req), t + 4 * MIN);
  await w.put("shared-id-01", "result", { job: "cf.token.canary", request: g.sha }, t + 5 * MIN);
  await w.put("shared-id-01", "op_result", doneRec(op.sha), t + 6 * MIN);
  await w.run(NOW);
  assert.deepEqual(w.ids().filter((i) => !i.startsWith("lock")), []);
});

test("row 11: the run is remembered when the grant map is full", async () => {
  const w = await world();
  const t = NOW - 3 * HOUR, req = await openRun(w, t);
  // MAX_OPEN newer grants already in the checker's map push the run-open request out of it.
  const open = Object.fromEntries(Array.from({ length: MAX_OPEN }, (_, i) => [`seeded-${String(i).padStart(6, "0")}`, { job: "cf.token.canary", req: "e".repeat(64), at: NOW - HOUR, stages: ["request"] }]));
  await w.copy.put(STATE_KEY, JSON.stringify({ seq: 0, open }));
  await w.run(NOW - 2 * HOUR);
  await w.put(OP, "op", opRec(req), NOW - 2 * HOUR + MIN);
  await w.run(NOW);
  assert.deepEqual(has(w.ids(), "op-"), [], "a run remembered only in the grant map raises op findings");
});

test("rows 12, 20 (W4, X2): no result after 24 h is incomplete only once a complete read passes it; gaps and higher numbers wait", async () => {
  const opAt = NOW - DAY - 30 * MIN;
  const setup = async () => { const w = await world(); const req = await openRun(w, opAt - 2 * MIN); await w.put(OP, "op", opRec(req), opAt); return w; };
  // Complete hour: raised. No later records are needed (N3).
  let w = await setup();
  await w.run(NOW);
  assert.ok(w.ids().includes(`op-incomplete:${OP}`));
  // Not yet 24 h + 10 min: waits.
  w = await setup();
  await w.run(opAt + DAY + 5 * MIN);
  assert.equal(has(w.ids(), "op-incomplete").length, 0);
  // A gap (a higher number with the next missing), or a higher number past the tail's first page: waits.
  w = await setup();
  w.skip();
  await w.put("grant-0009", "request", { job: "cf.token.canary" }, NOW - MIN);
  await w.run(NOW);
  assert.ok(has(w.ids(), "gap").length && !has(w.ids(), "op-incomplete").length);
  w = await setup();
  for (let i = 0; i < 1200; i++) w.b.store.set(`records/v1/${"0".repeat(11)}4.junk${i}`, { body: "x", uploaded: new Date(NOW) });
  w.b.store.set(`records/v1/000000999999.grant-0009.request.json`, { body: "x", uploaded: new Date(NOW) });
  await w.run(NOW);
  assert.equal(has(w.ids(), "op-incomplete").length, 0);
});

test("row 13: late, mismatched, duplicate and orphan results are findings; only a valid result clears the op", async () => {
  const w = await world();
  const t = NOW - 30 * HOUR, req = await openRun(w, t, { descriptor: desc(t, { deadline: t + 20 * HOUR }) });
  const a = await w.put("op-aaaaaaaa", "op", opRec(req), t + 2 * MIN);
  const b2 = await w.put("op-bbbbbbbb", "op", opRec(req), t + 3 * MIN);
  const c = await w.put("op-cccccccc", "op", opRec(req), t + 4 * MIN);
  await w.put("op-aaaaaaaa", "op_result", doneRec(b2.sha), t + 5 * MIN); // names another op's bytes
  await w.put("op-bbbbbbbb", "op_result", doneRec(b2.sha), t + 6 * MIN);
  await w.put("op-bbbbbbbb", "op_result", doneRec(b2.sha, { answer_sha256: "d".repeat(64) }), t + 7 * MIN); // a second, different result
  await w.put("op-cccccccc", "op_result", doneRec(c.sha), t + 4 * MIN + DAY + MIN); // over 24 h
  await w.put("op-dddddddd", "op_result", doneRec(a.sha), t + 8 * MIN);
  await w.run(NOW);
  const ids = w.ids();
  assert.ok(has(ids, "op-unlinked:op-aaaaaaaa").length && has(ids, "op-unlinked:op-dddddddd").length, "orphan results are not reported as unlinked");
  assert.ok(ids.includes("duplicate:o:op-bbbbbbbb:op_result"));
  assert.ok(has(ids, "op-late:op-cccccccc").length);
  assert.ok(ids.includes("op-incomplete:op-aaaaaaaa") && ids.includes("op-incomplete:op-cccccccc") && !ids.includes("op-incomplete:op-bbbbbbbb"));
});

test("row 14 (X1): an op stored 11 minutes late is never covered; a late-stored result never resolves its op", async () => {
  const w = await world();
  const t = NOW - DAY - HOUR, req = await openRun(w, t);
  await w.put("op-lateop01", "op", opRec(req), t + 2 * MIN, 11 * MIN);
  const ok = await w.put(OP, "op", opRec(req), t + 3 * MIN);
  await w.put(OP, "op_result", doneRec(ok.sha), t + 4 * MIN, 11 * MIN);
  await w.run(NOW);
  const ids = w.ids();
  assert.match(textOf(w, (id) => id.startsWith("op-uncovered:op-lateop01"), "late op uncovered"), /stored late/);
  assert.ok(ids.includes(`op-incomplete:${OP}`), "the late result did not resolve its op");
});

test("row 15: alert text names ops and runs by fingerprint, never by id, run name or zone", async () => {
  const w = await world();
  const req = await openRun(w, NOW - 3 * HOUR);
  await w.put(OP, "op", opRec(req, { card: "00000000" }), NOW - 2 * HOUR);
  await w.put("op-orphan001", "op_result", doneRec("e".repeat(64)), NOW - 2 * HOUR);
  await w.run(NOW);
  const text = w.incidents().map((i) => i.text).join("\n");
  for (const s of [OP, RG, RUN, ZONE.name, "op-orphan001"]) assert.ok(!text.includes(s), s);
});

test("row 16 (X4): 200 open ops today fill the op pool; one tap request is 4 of the tap pool; neither borrows", async () => {
  assert.deepEqual(poolUse(NOW, { tap: 1, op: 200 }, [{ opened: NOW, stored: 1 }], Array.from({ length: 200 }, () => ({ at: NOW }))), { tap: 4, op: 400, reserved_bytes: 203 * MAX_STORED_BYTES }, "poolUse does not count op holds in the op pool");
  assert.equal(poolUse(NOW, { tap: 0, op: 0 }, [{ opened: NOW - DAY - 1, stored: 1 }], [{ at: NOW - DAY - 1 }]).tap, 0, "expired reservations free their slots");
  const w = await world();
  const t = NOW - 30 * MIN, req = await openRun(w, t);
  for (let i = 0; i < 200; i++) await w.put(`op-${String(i).padStart(10, "0")}`, "op", opRec(req, {}), t + 2 * MIN + i * 100);
  const r = await w.run(NOW);
  assert.deepEqual(r.ops.pools_today, { tap: 4, op: 400 }, "pools_today shares or misses a pool"); // the run-open grant: 2 stored + 2 reserved
  assert.ok(w.ids().includes(`pool:op:2026-11-05:90`) && !has(w.ids(), "pool:tap").length);
  assert.equal(OP_DAY_CAP, 400);
});

test("row 17: storage alerts at 80/90% for the run cutoff and tap capacity; runway only after 7 full days", () => {
  // Numbers below are for a 1 GiB tap budget, passed explicitly; the default is the recorder's own budget.
  const GIB1 = 1024 ** 3;
  assert.equal(STORE_BUDGET_BYTES, 6 * GIB1);
  const s = loadOps({});
  s.written = 0.79 * GIB1;
  assert.deepEqual(capacityFindings(s, NOW, 0, GIB1).map((f) => f.id), []);
  assert.deepEqual(capacityFindings(s, NOW, 0.02 * GIB1, GIB1).map((f) => f.id), ["capacity:tap:80"], "tap capacity 80% alert missing");
  s.written = 0.91 * RUN_CUTOFF_BYTES;
  assert.deepEqual(capacityFindings(s, NOW, 0, 6 * 1024 ** 3).map((f) => f.id), ["capacity:run:90"]); // 4.55 of 6 GiB: tap under 80%
  s.written = 0.81 * 6 * 1024 ** 3;
  assert.deepEqual(capacityFindings(s, NOW, 0, 6 * 1024 ** 3).map((f) => f.id), ["capacity:run:90", "capacity:tap:80"]);
  // Runway: 1 GiB budget, 0.5 GiB used, 20 MiB a day -> ~25 days: critical, but only with 7 full days of data.
  s.written = 0.5 * GIB1;
  s.first = "2026-11-01";
  for (let i = 1; i <= 7; i++) s.bytes[new Date(NOW - i * DAY).toISOString().slice(0, 10)] = 20 * 1024 ** 2;
  assert.deepEqual(capacityFindings(s, NOW, 0, GIB1).map((f) => f.id), [], "runway reported before 7 full days of data");
  s.first = "2026-10-28";
  const f = capacityFindings(s, NOW, 0, GIB1);
  assert.deepEqual(f.map((x) => x.id), ["runway:tap:critical"]);
  assert.match(f[0].text, /Ben acts within 7 days/);
  for (let i = 1; i <= 7; i++) s.bytes[new Date(NOW - i * DAY).toISOString().slice(0, 10)] = 10 * 1024 ** 2; // ~51 days
  assert.deepEqual(capacityFindings(s, NOW, 0, GIB1).map((x) => x.id), ["runway:tap:warning"]);
});

test("row 18 (W6): a state from before A loads with empty run-op state and raises nothing new", async () => {
  const w = await world();
  await w.put("grant-0001", "request", { job: "cf.token.canary" }, NOW - HOUR);
  await w.copy.put(STATE_KEY, JSON.stringify({ seq: 0, open: {}, days: {}, incidents: [] }));
  const runs = loadOps({ seq: 0, open: {}, days: {}, incidents: [] }).runs;
  assert.ok(runs !== null && typeof runs === "object" && Object.keys(runs).length === 0, "pre-A state loads empty runs");
  const r = await w.run(NOW);
  assert.equal(r.records, "ran");
  assert.deepEqual(w.ids().filter((i) => !i.startsWith("lock")), []);
  assert.equal(r.ops.ops_open, 0);
  assert.ok(r.ops.bytes.written > 0);
});

test("Codex r1 #2: tap reservation ages are signed time: a request stored 9 minutes late still frees its slots 24 h after it was recorded", async () => {
  const w = await world();
  const t = NOW - DAY - 5 * MIN; // recorded 24 h 5 min ago, uploaded 23 h 56 min ago
  await w.put("grant-0001", "request", { job: "cf.token.canary" }, t, 9 * MIN);
  const r = await w.run(NOW);
  assert.equal(r.ops.pools_today.tap, 0, "a tap reservation was timed by upload, not recorded_at");
});

test("Codex r1 #3: over 400 op records in a UTC day is cap:op, and the tap pool is untouched", async () => {
  const w = await world();
  const t = NOW - 2 * HOUR;
  await w.put("grant-0001", "request", { job: "cf.token.canary" }, t);
  for (let i = 0; i <= OP_DAY_CAP; i++) await w.put(`op-${String(i).padStart(10, "0")}`, "op", opRec("e".repeat(64)), t + MIN + i * 10);
  const r = await w.run(NOW);
  // 401 unlinked ops outrank it on the 200-entry list, so it may sit in the overflow set the "more" line counts.
  const st = JSON.parse(w.copy.store.get(STATE_KEY)!.body), all = [...w.ids(), ...st.dropped];
  assert.ok(all.includes("cap:op:2026-11-05"));
  assert.ok(!all.some((i: string) => /^cap:\d/.test(i)), "no tap cap finding");
  assert.equal(r.ops.pools_today.tap, 4);
});

test("Codex r1 #4: a watermark stalled over 7 days lets run-op state go as unsettled, never as incomplete", async () => {
  const w = await world();
  const t = NOW - 8 * DAY - HOUR, req = await openRun(w, t);
  await w.put(OP, "op", opRec(req), t + 2 * MIN);
  w.b.store.set(`records/v1/000000999999.grant-0009.request.json`, { body: "x", uploaded: new Date(NOW) }); // holds the watermark
  let r = await w.run(t + HOUR);
  assert.equal(r.ops.ops_open, 1);
  r = await w.run(NOW);
  assert.deepEqual([r.ops.ops_open, r.ops.runs_open], [0, 0], "stalled watermark: run-op state kept or not let go as unsettled");
  assert.ok(w.ids().includes(`op-unsettled:${OP}`) && !has(w.ids(), "op-incomplete").length);
  assert.ok(!w.incidents().some((i) => i.text.includes(OP)), "named by fingerprint only");
});

test("commit security review: an op first read after a week-long backlog is held 7 days from its reading, so its result still links", async () => {
  const w = await world();
  const t = NOW - 8 * DAY - HOUR, req = await openRun(w, t);
  const op = await w.put(OP, "op", opRec(req), t + 2 * MIN);
  w.b.store.set(`records/v1/000000999999.grant-0009.request.json`, { body: "x", uploaded: new Date(NOW) }); // holds the watermark
  let r = await w.run(NOW); // first read of the op, 8 days after it was recorded
  assert.equal(r.ops.ops_open, 1, "an op hold was timed from first read, not recorded_at");
  await w.put(OP, "op_result", doneRec(op.sha), t + 3 * MIN);
  r = await w.run(NOW + HOUR);
  assert.equal(r.ops.results, 1);
  assert.deepEqual(has(w.ids(), "op-u"), []);
});
