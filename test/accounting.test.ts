// B1 (card 509a5d85): the recorder's accounting for runs. Two pools, expiry on every turn, re-time sync,
// one-transaction withdrawals, legacy bytes, status fields, and recorder status vs the checker's poolUse
// while a record is pending. Section ids are REFINE-observatory-ops.md v5-v11; threat rows T11-T15 are v5 Y7.
import { test } from "node:test";
import assert from "node:assert/strict";
import { DAY_CAP, GRANT_TTL_MS, keyFor, MAX_STORED_BYTES, sha256, STAGE_SLOTS, STORE_BUDGET_BYTES } from "../src/contract.ts";
import { Ledger, REFUSALS } from "../src/recorder/ledger.ts";
import { OP_DAY_CAP, poolUse, RUN_CUTOFF_BYTES } from "../src/ops.ts";
import { bucket, storage } from "./store.ts";
import { openRun, opBody, runLedger } from "./runs.ts";

type St = ReturnType<typeof storage>;
type B = ReturnType<typeof bucket>;
interface Meta { seq: number; day: string; used: number; bytes: number; open: { grant: string; opened: number; left: number }[]; op_used?: number; op_open?: { op: string; at: number; left: number }[]; expired?: { tap: number; op: number } }
interface Pend { key: string; stored: string; storedSha: string; receipt: { seq: number; recorded_at: string; grant: string; stage: string }; day: string; pool?: string }

const T = (iso: string) => () => new Date(iso);
const ms = (iso: string) => Date.parse(iso);
const len = (s: string) => new TextEncoder().encode(s).length;
const rec = (stage: string, grant: string, over: object = {}) => JSON.stringify({ v: 1, grant, stage, job: "cf.token.canary", ...over });
const meta = (st: St) => st.m.get("meta") as Meta;
const grantOf = (st: St, g: string) => st.m.get(`g:${g}`) as { opened: number; stages: Record<string, { recorded_at: string; seq: number }> };
const hold = (st: St, g: string) => meta(st).open.find((o) => o.grant === g);
const storedBytes = (b: B) => [...b.store.values()].reduce((n, v) => n + len(v.body), 0);

function ledger() {
  const st = storage(), b = bucket();
  return { st, b, l: new Ledger(st, b, STORE_BUDGET_BYTES, async () => undefined) };
}
/** A request for `g` stored at `iso`; returns the hash later stages name. */
async function opened(l: Ledger, g: string, iso: string) {
  const body = rec("request", g);
  assert.equal((await l.accept(body, T(iso))).status, 201);
  return sha256(body);
}

/** The checker's view at `now`, from the bucket alone (A's poolUse inputs: charged by recorded_at day). */
function checker(b: B, now: number) {
  const env = [...b.store.values()].map((v) => JSON.parse(v.body) as { grant: string; stage: string; recorded_at: string });
  const today = new Date(now).toISOString().slice(0, 10);
  const grants = new Map<string, { opened: number; stored: number }>();
  for (const e of env) {
    const g = grants.get(e.grant) ?? { opened: NaN, stored: 0 };
    if (e.stage === "request") g.opened = ms(e.recorded_at);
    g.stored += 1;
    grants.set(e.grant, g);
  }
  const taps = [...grants.values()].filter((g) => !Number.isNaN(g.opened));
  return { use: poolUse(now, { tap: env.filter((e) => e.recorded_at.slice(0, 10) === today).length, op: 0 }, taps, []), grants };
}
/**
 * AB1's identity, from the recorder's own state: for pending P at `now`, recorder tap-pool slots minus the
 * checker's = q + (recorder holds) - (checker holds), q = 1 if P's object is absent and P is charged today.
 */
function expectedDiff(st: St, b: B, now: number) {
  const p = st.m.get("pending") as Pend | undefined;
  if (!p) return 0;
  const absent = !b.store.has(p.key), today = new Date(now).toISOString().slice(0, 10);
  const q = absent && p.day === today ? 1 : 0;
  const rHolds = hold(st, p.receipt.grant)?.left ?? 0;
  const c = checker(b, now).grants.get(p.receipt.grant);
  const cHolds = c && !Number.isNaN(c.opened) && now - c.opened <= GRANT_TTL_MS ? Math.max(0, STAGE_SLOTS - c.stored) : 0;
  return q + rHolds - cHolds;
}
async function compare(l: Ledger, st: St, b: B, iso: string, want: number) {
  const s = await l.status(() => new Date(iso)), c = checker(b, ms(iso)).use, d = expectedDiff(st, b, ms(iso));
  assert.equal(d, want, "the pending identity gives the table's number for this case");
  assert.equal(s.pools.tap.used - c.tap, d, "recorder tap pool minus checker poolUse differs from the pending identity (REFINE v8 AB1)");
  const p = st.m.get("pending") as Pend | undefined, g = p ? checker(b, ms(iso)).grants.get(p.receipt.grant) : undefined;
  const rHolds = p ? (hold(st, p.receipt.grant)?.left ?? 0) : 0;
  const cHolds = g && !Number.isNaN(g.opened) && ms(iso) - g.opened <= GRANT_TTL_MS ? Math.max(0, STAGE_SLOTS - g.stored) : 0;
  assert.equal(s.pools.tap.reserved_bytes - c.reserved_bytes, (rHolds - cHolds) * MAX_STORED_BYTES, "reserved bytes do not follow the holds (AB1)");
  assert.equal(s.stored_bytes - storedBytes(b), p && !b.store.has(p.key) ? len(p.stored) : 0, "stored bytes differ by more than the absent pending envelope (AB1)");
}

// ---- pools, budget and status (Y6, Z5, AA3) ----

test("status shows both pools (op pool empty), 6 GiB budget, 5 GiB op cutoff, pending bytes and every counter", async () => {
  const { l, b } = ledger();
  await opened(l, "grant-st-01", "2026-11-01T12:00:00Z");
  const s = await l.status(() => new Date("2026-11-01T12:01:00Z"));
  assert.deepEqual(s.pools, {
    tap: { used: STAGE_SLOTS, cap: DAY_CAP, reserved_slots: STAGE_SLOTS - 1, reserved_bytes: (STAGE_SLOTS - 1) * MAX_STORED_BYTES },
    op: { used: 0, cap: OP_DAY_CAP, reserved_slots: 0, reserved_bytes: 0 },
  });
  assert.equal(s.used_today, STAGE_SLOTS); // the old name stays the tap pool, for the desk's reader
  assert.deepEqual([s.budget_bytes, s.op_cutoff_bytes, s.stored_bytes, s.pending_bytes], [6 * 1024 ** 3, 5 * 1024 ** 3, storedBytes(b), 0]);
  assert.equal(RUN_CUTOFF_BYTES < STORE_BUDGET_BYTES, true);
  assert.deepEqual(s.refused, Object.fromEntries(REFUSALS.map((r) => [r, 0])));
  assert.deepEqual([s.retries, s.expired], [0, { tap: 0, op: 0 }]);
});

test("refusals are counted by fixed reason word and identical retries apart", async () => {
  const { l, b } = ledger();
  const body = rec("request", "grant-rf-01");
  await l.accept(body, T("2026-11-01T12:00:00Z"));
  assert.equal((await l.accept(body, T("2026-11-01T12:00:01Z"))).status, 200);
  assert.equal((await l.accept("{", T("2026-11-01T12:00:02Z"))).status, 400);
  assert.equal((await l.accept(rec("approval", "grant-rf-02", { request: "a".repeat(64) }), T("2026-11-01T12:00:03Z"))).status, 409);
  b.failNext(2);
  assert.equal((await l.accept(rec("request", "grant-rf-03"), T("2026-11-01T12:00:04Z"))).status, 503);
  const s = await l.status(() => new Date("2026-11-01T12:00:05Z"));
  assert.deepEqual([s.refused.invalid, s.refused.conflict, s.refused.stuck, s.retries], [1, 1, 1, 1], "refusal or retry not counted by its reason");
  assert.ok(s.pending_bytes > 0, "pending_bytes is 0 while a record is pending");
});

test("a pool refusal is counted as tap_pool_full; a full budget as budget_full", async () => {
  const st = storage(), b = bucket(), l = new Ledger(st, b, 4 * MAX_STORED_BYTES + 10, async () => undefined);
  await l.accept(rec("request", "grant-pf-01"), T("2026-11-01T12:00:00Z"));
  assert.equal((await l.accept(rec("request", "grant-pf-02"), T("2026-11-01T12:00:01Z"))).status, 429);
  const m = meta(st);
  st.m.set("meta", { ...m, used: DAY_CAP });
  assert.equal((await l.accept(rec("request", "grant-pf-03"), T("2026-11-01T12:00:02Z"))).status, 429);
  const s = await l.status(() => new Date("2026-11-01T12:00:03Z"));
  assert.deepEqual([s.refused.budget_full, s.refused.tap_pool_full], [1, 1], "429 reasons not told apart");
});

test("status reads its clock in its own turn, after the write queued before it (REFINE v6 Z5)", async () => {
  const { l } = ledger();
  const order: string[] = [];
  const write = l.accept(rec("request", "grant-ck-01"), () => { order.push("write"); return new Date("2026-11-01T12:00:00Z"); });
  const status = l.status(() => { order.push("status"); return new Date("2026-11-01T12:00:01Z"); });
  order.push("queued");
  await Promise.all([write, status]);
  assert.deepEqual(order, ["queued", "write", "status"], "status read the clock before its turn");
});

test("status queued behind a write that stalls across midnight reports the new day (Codex B1 r1 #1)", async () => {
  const st = storage(), b = bucket();
  let release!: () => void, entered!: () => void;
  const gate = new Promise<void>((r) => (release = r)), inPut = new Promise<void>((r) => (entered = r));
  const slow = { ...b, async put(k: string, body: string, o?: R2PutOptions) { entered(); await gate; return b.put(k, body, o); } };
  const l = new Ledger(st, slow, STORE_BUDGET_BYTES, async () => undefined);
  let now = ms("2026-11-01T23:59:59Z");
  const clock = () => new Date(now);
  const write = l.accept(rec("request", "grant-ck-02"), clock);
  const status = l.status(clock);
  await inPut; // the bucket write has started and is held (Codex B1 r2 later)
  now = ms("2026-11-02T00:00:30Z"); // the bucket write is still out when midnight passes
  release();
  assert.equal((await write).status, 201);
  const s = await status;
  assert.equal(s.pools.tap.used, STAGE_SLOTS - 1, "status used a time taken before its turn (it counted yesterday's charge)");
});

// ---- expiry (V6.3, T13) ----

test("T13: a hold lasts exactly 24 h, inclusive; at 24 h + 1 ms it is released the same day and counted once", async () => {
  const { l, st } = ledger();
  await opened(l, "grant-ex-01", "2026-11-01T10:00:00Z");
  // A write on day 2 first, so the stored day is already day 2: expiry must happen within the day,
  // not only at a rollover (Codex B1 r1 #2).
  await opened(l, "grant-ex-00", "2026-11-02T09:00:00Z");
  assert.equal(meta(st).day, "2026-11-02");
  const at24 = await l.status(() => new Date("2026-11-02T10:00:00.000Z"));
  assert.deepEqual([at24.pools.tap.used, at24.pools.tap.reserved_slots], [2 * STAGE_SLOTS - 1, 2 * (STAGE_SLOTS - 1)], "hold released at exactly 24 h");
  const past = await l.status(() => new Date("2026-11-02T10:00:00.001Z"));
  assert.deepEqual([past.pools.tap.used, past.pools.tap.reserved_slots, past.expired.tap], [STAGE_SLOTS, STAGE_SLOTS - 1, 1], "hold kept past 24 h within the stored day");
  const again = await l.status(() => new Date("2026-11-02T11:00:00Z"));
  assert.equal(again.expired.tap, 1, "an expired hold was counted twice");
  await opened(l, "grant-ex-09", "2026-11-02T12:00:00Z");
  assert.deepEqual([meta(st).expired!.tap, meta(st).open.map((o) => o.grant)], [1, ["grant-ex-00", "grant-ex-09"]], "the next accept did not store the release once");
});

test("expiry also runs on accept: a request admitted the day after counts only live holds", async () => {
  const { l, st } = ledger();
  await opened(l, "grant-ex-02", "2026-11-01T10:00:00Z");
  await opened(l, "grant-ex-03", "2026-11-02T10:30:00Z");
  assert.deepEqual([meta(st).used, meta(st).expired!.tap, meta(st).open.map((o) => o.grant)], [STAGE_SLOTS, 1, ["grant-ex-03"]]);
});

test("a later stage at exactly 24 h is taken; at 24 h + 1 ms it is refused (same rule as the hold)", async () => {
  const { l } = ledger();
  const h = await opened(l, "grant-ex-04", "2026-11-01T10:00:00Z");
  assert.equal((await l.accept(rec("verdict", "grant-ex-04", { request: h }), T("2026-11-02T10:00:00.000Z"))).status, 201);
  assert.equal((await l.accept(rec("approval", "grant-ex-04", { request: h }), T("2026-11-02T10:00:00.001Z"))).status, 410);
});


// ---- re-time sync and long stalls (T11, Z4, AA2) ----

test("T11: a request stored 6 min late moves its grant's opening time and its hold to when it was stored", async () => {
  const { l, st, b } = ledger();
  b.failNext();
  assert.equal((await l.accept(rec("request", "grant-rt-01"), T("2026-11-01T12:00:00Z"))).status, 503);
  await opened(l, "grant-rt-02", "2026-11-01T12:06:00Z");
  const stored = JSON.parse(b.store.get(keyFor(1, "grant-rt-01", "request"))!.body) as { recorded_at: string };
  assert.equal(stored.recorded_at, "2026-11-01T12:06:00.000Z");
  assert.equal(grantOf(st, "grant-rt-01").opened, ms(stored.recorded_at), "re-timed request kept its old opening time");
  assert.equal(hold(st, "grant-rt-01")!.opened, ms(stored.recorded_at), "re-timed request kept its hold's old start");
});

for (const reads of [false, true]) {
  test(`Z4: a request pending 24 h + 1 ms${reads ? " with status reads in between" : ""} is stored holding 3 from its new time`, async () => {
    const { l, st, b } = ledger();
    b.failNext(reads ? 99 : 1);
    await l.accept(rec("request", "grant-st-10"), T("2026-11-01T12:00:00Z"));
    if (reads) {
      for (const iso of ["2026-11-01T23:00:00Z", "2026-11-02T12:00:00.001Z", "2026-11-02T13:00:00Z"]) {
        const s = await l.status(() => new Date(iso));
        assert.equal(s.pools.tap.reserved_slots, STAGE_SLOTS - 1, `status at ${iso} released the pending record's hold`);
      }
      b.failNext(0);
    }
    const back = "2026-11-02T14:00:00.000Z";
    await opened(l, "grant-st-11", back);
    assert.equal(grantOf(st, "grant-st-10").opened, ms(back));
    assert.deepEqual(hold(st, "grant-st-10"), { grant: "grant-st-10", opened: ms(back), left: STAGE_SLOTS - 1 });
    assert.equal(meta(st).used, 2 * STAGE_SLOTS, "re-charged request: 3 carried + 1 today, plus the new grant's 4");
    assert.equal(meta(st).expired!.tap, 0);
    const later = await l.status(() => new Date("2026-11-03T14:00:00.000Z"));
    assert.equal(later.pools.tap.reserved_slots, 2 * (STAGE_SLOTS - 1), "the re-timed hold ran out before its new 24 h");
  });
}

test("Z4: a request pending across midnight is charged once to the new day (3 carried + 1), its window from then", async () => {
  const { l, st, b } = ledger();
  b.failNext();
  await l.accept(rec("request", "grant-mn-01"), T("2026-11-01T23:58:00Z"));
  const s = await l.status(() => new Date("2026-11-02T00:01:00Z"));
  assert.equal(s.pools.tap.used, STAGE_SLOTS - 1); // only the hold carries; the record is charged when stored
  await l.accept(rec("verdict", "grant-zz-zz", { request: "a".repeat(64) }), T("2026-11-02T00:03:00Z"));
  assert.equal(meta(st).used, STAGE_SLOTS);
  assert.equal(grantOf(st, "grant-mn-01").opened, ms("2026-11-02T00:03:00Z"));
});

test("AA2: a verdict stored 6 min late inside its window is stored; its grant's opening time does not move", async () => {
  const { l, st, b } = ledger();
  const h = await opened(l, "grant-vl-01", "2026-11-01T12:00:00Z");
  b.failNext();
  await l.accept(rec("verdict", "grant-vl-01", { request: h }), T("2026-11-01T13:00:00Z"));
  await opened(l, "grant-vl-02", "2026-11-01T13:06:00Z");
  assert.equal(grantOf(st, "grant-vl-01").opened, ms("2026-11-01T12:00:00Z"), "a later stage moved its parent's opening time");
  assert.equal(grantOf(st, "grant-vl-01").stages.verdict.recorded_at, "2026-11-01T13:06:00.000Z");
});

/** An approval for a grant opened day 1 at noon, left pending at day 2 11:54 (charged day 2, hold 2). */
async function lateApproval() {
  const x = ledger();
  const h = await opened(x.l, "grant-la-01", "2026-11-01T12:00:00Z");
  x.b.failNext();
  assert.equal((await x.l.accept(rec("approval", "grant-la-01", { request: h }), T("2026-11-02T11:54:00Z"))).status, 503);
  const before = structuredClone({ meta: meta(x.st), g: grantOf(x.st, "grant-la-01"), pending: x.st.m.get("pending") });
  const requestBytes = len(x.b.store.get(keyFor(1, "grant-la-01", "request"))!.body);
  return { ...x, h, before, requestBytes };
}
const RECOVER = "2026-11-02T12:00:00.001Z"; // 6 min late and 1 ms past the grant's 24 h

function assertWithdrawn(st: St, b: B, requestBytes: number, nextSeq: number) {
  assert.equal(grantOf(st, "grant-la-01").stages.approval, undefined, "late stage still on its grant");
  assert.equal(grantOf(st, "grant-la-01").opened, ms("2026-11-01T12:00:00Z"), "late withdrawal moved the opening time");
  assert.equal(st.m.has("pending"), false);
  assert.equal(hold(st, "grant-la-01"), undefined, "the late grant's hold was kept or restored");
  assert.equal(meta(st).expired!.tap, 1, "the released hold was not counted once as expired");
  assert.equal([...b.store.keys()].some((k) => k.includes("grant-la-01.approval")), false, "late stage written");
  assert.equal(meta(st).seq, nextSeq);
  assert.equal(meta(st).bytes, requestBytes + (nextSeq === 2 ? len(b.store.get(keyFor(2, "grant-la-02", "request"))!.body) : 0), "bytes not reconciled");
  assert.equal(meta(st).used, nextSeq === 2 ? STAGE_SLOTS : 0, "today's tap pool not reconciled");
}

test("AA2/AB2: a later stage re-timed 1 ms past its grant's 24 h is withdrawn: number, bytes, charge back; hold released", async () => {
  const { l, st, b, requestBytes } = await lateApproval();
  await opened(l, "grant-la-02", RECOVER);
  assertWithdrawn(st, b, requestBytes, 2);
  assert.equal(b.store.has(keyFor(2, "grant-la-02", "request")), true, "the next record did not reuse the given-back number");
});

test("AA2: the writer's own retry of a withdrawn late stage is refused as over 24 hours (410)", async () => {
  const { l, h } = await lateApproval();
  const out = await l.accept(rec("approval", "grant-la-01", { request: h }), T(RECOVER));
  assert.deepEqual(out, { status: 410, why: "this grant's request is over 24 hours old" });
});

test("AE1: a fault inside the late withdrawal changes nothing; the next turn withdraws once", async () => {
  const { l, st, b, before, requestBytes } = await lateApproval();
  st.fault("pending");
  assert.equal((await l.accept(rec("request", "grant-la-02"), T(RECOVER))).status, 503);
  assert.deepEqual({ meta: meta(st), g: grantOf(st, "grant-la-01"), pending: st.m.get("pending") }, before, "a fault inside the late withdrawal left part of it applied");
  await opened(l, "grant-la-02", "2026-11-02T12:00:01Z");
  assertWithdrawn(st, b, requestBytes, 2);
});

test("AE1: with a conflicting object planted at its name, the late stage is retagged, then withdrawn once", async () => {
  const { l, st, b, requestBytes } = await lateApproval();
  const p = st.m.get("pending") as Pend;
  b.store.set(p.key, { body: "planted" });
  st.fault("pending", 1); // the retag's put passes; the withdrawal's delete dies
  assert.equal((await l.accept(rec("request", "grant-la-02"), T(RECOVER))).status, 503);
  await opened(l, "grant-la-02", "2026-11-02T12:00:01Z");
  b.store.delete(p.key); // the plant is not ours; drop it so the byte check counts only recorder writes
  assertWithdrawn(st, b, requestBytes, 2);
});

// ---- the live #withdrawUnverified fix and its cross-day count ----

test("an unverified approval charged yesterday, withdrawn today, goes back to today's pool (found writing B1)", async () => {
  const st = storage(), b = bucket();
  let refuse = false;
  const l = new Ledger(st, b, STORE_BUDGET_BYTES, async () => (refuse ? "no passkey" : undefined));
  const h = await opened(l, "grant-uv-01", "2026-11-01T22:00:00Z");
  b.failNext();
  await l.accept(rec("approval", "grant-uv-01", { request: h }), T("2026-11-01T23:59:00Z"));
  refuse = true;
  await opened(l, "grant-uv-02", "2026-11-02T00:01:00Z");
  assert.equal(hold(st, "grant-uv-01")!.left, STAGE_SLOTS - 1);
  assert.equal(meta(st).used, (STAGE_SLOTS - 1) + STAGE_SLOTS, "today's pool reads one low after a cross-day withdrawal");
  const s = await l.status(() => new Date("2026-11-02T00:02:00Z"));
  const c = checker(b, ms("2026-11-02T00:02:00Z")).use;
  assert.equal(s.pools.tap.used, c.tap, "recorder and checker disagree with nothing pending");
});

// ---- legacy bytes (V6.7, Z5) ----

for (const retimed of [false, true]) {
  test(`Z5: a legacy unsigned pending record${retimed ? " re-timed" : ""} is charged its new length when signed`, async () => {
    const { l, st, b } = ledger();
    const h = await opened(l, "grant-lg-01", "2026-11-01T12:00:00Z");
    b.failNext();
    await l.accept(rec("verdict", "grant-lg-01", { request: h }), T("2026-11-01T12:01:00Z"));
    const p = st.m.get("pending") as Pend, old = JSON.parse(p.stored);
    delete old.sig;
    old.v = 1;
    const legacy = JSON.stringify(old);
    st.m.set("pending", { ...p, stored: legacy, storedSha: await sha256(legacy) });
    st.m.set("meta", { ...meta(st), bytes: meta(st).bytes - len(p.stored) + len(legacy) });
    await opened(l, "grant-lg-02", retimed ? "2026-11-01T12:30:00Z" : "2026-11-01T12:02:00Z");
    assert.equal(meta(st).bytes, storedBytes(b), "stored bytes and the budget count differ after signing a legacy record");
  });
}

// ---- T15: pool-aware midnight re-charge (B2: a real admitted op; B1 planted the state) ----

/** A ledger with run ops on, a run opened at 23:00 and an op left pending at 23:59 (its bucket write failed). */
async function pendingOpAtMidnight() {
  const w = runLedger();
  const t0 = ms("2026-11-01T23:00:00Z");
  const req = await openRun(w.l, t0);
  w.b.failNext(1);
  assert.equal((await w.l.accept(opBody("op-0000000001", req), T("2026-11-01T23:59:00Z"))).status, 503);
  return w;
}

test("T15: a pending op stored on a later day is charged to the op pool, never the tap pool", async () => {
  const { l, st } = await pendingOpAtMidnight();
  await l.status(() => new Date("2026-11-02T00:01:00Z"));
  await opened(l, "grant-op-01", "2026-11-02T00:02:00Z");
  // The new day: the op's own slot + its carried hold in the op pool; the run's carried 2 + the new request's 4 in the tap pool.
  assert.deepEqual([meta(st).op_used, meta(st).used], [1 + 1, (STAGE_SLOTS - 2) + STAGE_SLOTS], "op re-charged to the wrong pool");
});

test("T15: a pending op meets a full op pool on its new day: it waits (503), the tap pool untouched", async () => {
  const { l, st } = await pendingOpAtMidnight();
  st.m.set("meta", { ...meta(st), day: "2026-11-02", used: STAGE_SLOTS - 2, op_used: OP_DAY_CAP });
  const out = await l.accept(rec("request", "grant-op-11"), T("2026-11-02T00:02:00Z"));
  assert.deepEqual(out, { status: 503, why: `today's ${OP_DAY_CAP} op slots are taken; the pending record waits` }, "a pending op was stored past a full op pool");
  assert.deepEqual([meta(st).used, meta(st).op_used, st.m.has("pending")], [STAGE_SLOTS - 2, OP_DAY_CAP, true]);
});

// ---- AB1: recorder status vs the checker's poolUse while a record is pending ----

test("AB1: absent request, same day: +4 (q + 3)", async () => {
  const { l, st, b } = ledger();
  b.failNext(99);
  await l.accept(rec("request", "grant-ab-01"), T("2026-11-01T12:00:00Z"));
  await compare(l, st, b, "2026-11-01T12:01:00Z", 4);
});
test("AB1: absent request across midnight: +3, not +4", async () => {
  const { l, st, b } = ledger();
  b.failNext(99);
  await l.accept(rec("request", "grant-ab-02"), T("2026-11-01T23:59:00Z"));
  await compare(l, st, b, "2026-11-02T00:01:00Z", 3);
});
test("AB1: absent approval, parent within 24 h: same day 0 (q - 1); pending from yesterday -1", async () => {
  for (const [later, want] of [["2026-11-01T12:10:00Z", 0], ["2026-11-02T00:10:00Z", -1]] as const) {
    const { l, st, b } = ledger();
    const h = await opened(l, "grant-ab-03", "2026-11-01T12:00:00Z");
    b.failNext(99);
    await l.accept(rec("approval", "grant-ab-03", { request: h }), T("2026-11-01T12:05:00Z"));
    await compare(l, st, b, later, want);
  }
});
test("AB1: result pending at 11:59 for a grant opened yesterday at noon, status at 12:01: +1", async () => {
  const { l, st, b } = ledger();
  const h = await opened(l, "grant-ab-04", "2026-11-01T12:00:00Z");
  for (const [s, iso] of [["approval", "2026-11-01T12:01:00Z"], ["verdict", "2026-11-01T12:02:00Z"]]) assert.equal((await l.accept(rec(s!, "grant-ab-04", { request: h }), T(iso!))).status, 201);
  b.failNext(99);
  await l.accept(rec("result", "grant-ab-04", { request: h }), T("2026-11-02T11:59:00Z"));
  await compare(l, st, b, "2026-11-02T12:01:00Z", 1);
});
test("AB1: approval pending past the checker's 24 h, recorder retains 2: q + 2", async () => {
  const { l, st, b } = ledger();
  const h = await opened(l, "grant-ab-05", "2026-11-01T12:00:00Z");
  b.failNext(99);
  await l.accept(rec("approval", "grant-ab-05", { request: h }), T("2026-11-02T11:59:00Z"));
  await compare(l, st, b, "2026-11-02T12:01:00Z", 3);
});
test("AB1: exact object present (crash after the bucket write): 0; still pending after 24 h: +3", async () => {
  for (const [iso, want] of [["2026-11-01T12:01:00Z", 0], ["2026-11-02T12:00:01Z", 3]] as const) {
    const { l, st, b } = ledger();
    st.fault("pending", 1); // admission's put passes; the delete after the bucket write dies
    await assert.rejects(l.accept(rec("request", "grant-ab-06"), T("2026-11-01T12:00:00Z")));
    assert.equal(st.m.has("pending") && b.store.size === 1, true);
    await compare(l, st, b, iso, want);
  }
});
test("AB1: nothing pending: recorder and checker agree exactly", async () => {
  const { l, st, b } = ledger();
  const h = await opened(l, "grant-ab-07", "2026-11-01T12:00:00Z");
  await l.accept(rec("verdict", "grant-ab-07", { request: h }), T("2026-11-01T12:01:00Z"));
  await compare(l, st, b, "2026-11-01T12:02:00Z", 0);
  await opened(l, "grant-ab-08", "2026-11-02T08:00:00Z");
  for (const iso of ["2026-11-02T09:00:00Z", "2026-11-02T12:00:00.000Z", "2026-11-02T12:00:00.001Z"]) await compare(l, st, b, iso, 0);
});

// ---- AE1 for #withdrawUnverified, and the delete held inside each transaction (Codex B1 r1 #3) ----

/** An approval for a grant opened at noon, left pending at 12:05 (bucket down), then judged unverified. */
async function unverifiedApproval() {
  const st = storage(), b = bucket();
  let refuse = false;
  const l = new Ledger(st, b, STORE_BUDGET_BYTES, async () => (refuse ? "no passkey" : undefined));
  const h = await opened(l, "grant-uw-01", "2026-11-01T12:00:00Z");
  b.failNext();
  assert.equal((await l.accept(rec("approval", "grant-uw-01", { request: h }), T("2026-11-01T12:05:00Z"))).status, 503);
  refuse = true;
  const requestBytes = len(b.store.get(keyFor(1, "grant-uw-01", "request"))!.body);
  return { st, b, l, h, requestBytes };
}
function assertUnverifiedWithdrawn(st: St, b: B, requestBytes: number) {
  assert.equal(st.m.has("pending"), false, "pending survived a committed withdrawal");
  assert.equal(grantOf(st, "grant-uw-01").stages.approval, undefined, "an approval receipt was re-created for a record never written");
  assert.equal([...b.store.keys()].some((k) => k.includes("grant-uw-01.approval")), false, "the unverified approval was written");
  assert.deepEqual([meta(st).seq, meta(st).bytes, meta(st).used, hold(st, "grant-uw-01")!.left], [1, requestBytes, STAGE_SLOTS, STAGE_SLOTS - 1], "unverified withdrawal totals not reconciled once");
}

test("AE1: unverified approval, a conflicting object planted at its name, a fault inside the withdrawal: nothing applied; then withdrawn once", async () => {
  const { st, b, l, requestBytes } = await unverifiedApproval();
  const p = st.m.get("pending") as Pend;
  b.store.set(p.key, { body: "planted" });
  st.fault("pending", 1); // the retag's put passes; the withdrawal's delete dies
  assert.equal((await l.accept("{", T("2026-11-01T12:06:00Z"))).status, 503);
  const retagged = st.m.get("pending") as Pend;
  assert.notEqual(retagged.key, p.key, "the planted name was not retagged first");
  assert.equal(grantOf(st, "grant-uw-01").stages.approval?.seq, 2, "a fault inside the withdrawal left part of it applied");
  assert.equal((await l.accept("{", T("2026-11-01T12:07:00Z"))).status, 400); // the next turn withdraws, then refuses the bad body
  b.store.delete(p.key);
  assertUnverifiedWithdrawn(st, b, requestBytes);
});

test("AE1: a committed unverified withdrawal removes pending in the same step, even when the turn's own record is refused", async () => {
  const { st, b, l, requestBytes } = await unverifiedApproval();
  assert.equal((await l.accept("{", T("2026-11-01T12:06:00Z"))).status, 400);
  assertUnverifiedWithdrawn(st, b, requestBytes);
  assert.equal((await l.accept("{", T("2026-11-01T12:07:00Z"))).status, 400); // a second turn changes nothing
  assertUnverifiedWithdrawn(st, b, requestBytes);
});

test("AE1: a committed late withdrawal removes pending in the same step, even when the turn's own record is refused", async () => {
  const { l, st, b, requestBytes } = await lateApproval();
  assert.equal((await l.accept("{", T(RECOVER))).status, 400);
  assert.equal(st.m.has("pending"), false, "pending survived a committed withdrawal");
  assert.equal((await l.accept("{", T("2026-11-02T12:00:01Z"))).status, 400);
  assertWithdrawn(st, b, requestBytes, 1);
});

test("unverified AND late: withdrawn as unverified, then its grant's hold expires on the same turn, counted once", async () => {
  const st = storage(), b = bucket();
  let refuse = false;
  const l = new Ledger(st, b, STORE_BUDGET_BYTES, async () => (refuse ? "no passkey" : undefined));
  const h = await opened(l, "grant-ul-01", "2026-11-01T12:00:00Z");
  b.failNext();
  await l.accept(rec("approval", "grant-ul-01", { request: h }), T("2026-11-02T11:54:00Z"));
  refuse = true;
  await opened(l, "grant-ul-02", RECOVER);
  assert.equal(grantOf(st, "grant-ul-01").stages.approval, undefined);
  assert.deepEqual([meta(st).seq, meta(st).used, meta(st).expired!.tap, hold(st, "grant-ul-01")], [2, STAGE_SLOTS, 1, undefined], "unverified-and-late withdrawal totals not reconciled");
  const s = await l.status(() => new Date(RECOVER));
  assert.equal(s.pools.tap.used, checker(b, ms(RECOVER)).use.tap, "recorder and checker disagree after an unverified-and-late withdrawal");
});
