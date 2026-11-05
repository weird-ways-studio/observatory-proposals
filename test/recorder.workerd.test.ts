// B1's start gate (REFINE-observatory-ops.md v11 AE1, v12): Durable Object `transaction` is all-or-nothing
// in the real runtime -- workerd from wrangler's own Miniflare, offline, on a SQLite-backed object, through
// the same Storage cast the live recorder uses. If this fails, the withdrawal design does not hold.
// Harness: test/workerd/txn-harness.ts (bundled with esbuild into a temp dir; never deployed).
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

const dir = mkdtempSync(join(tmpdir(), "obs-txn-"));
after(() => rmSync(dir, { recursive: true, force: true }));

async function start(name: string, harness = "txn-harness", className = "TxnBox") {
  const out = join(dir, `bundle-${name}`);
  await build({ entryPoints: [new URL(`./workerd/${harness}.ts`, import.meta.url).pathname], bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:workers"], outdir: out, logLevel: "silent" });
  const mf = new Miniflare(convertV4MiniflareOptions({
    modules: true, script: readFileSync(join(out, `${harness}.js`), "utf8"), compatibilityDate: "2026-10-01",
    durableObjects: { BOX: { className, useSQLite: true } }, r2Buckets: ["RECORDS"], resourcePersistencePath: join(dir, name),
  }));
  const send = async (...cmds: { method: string; args?: unknown[] }[]) =>
    (await (await mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify(cmds.map((c) => ({ args: [], ...c }))) })).json()) as any[];
  return { mf, send };
}

test("workerd transaction: a throw after the put leaves the accounting and pending exactly as before", { timeout: 60_000 }, async () => {
  const { mf, send } = await start("fault");
  try {
    const [, r, d] = await send({ method: "seed" }, { method: "withdraw", args: [true] }, { method: "dump" });
    assert.equal(r, "threw: injected fault after the put");
    assert.deepEqual(d, { meta: { seq: 7, used: 4, bytes: 900 }, pending: { key: "k7", seq: 7 } }, "workerd transaction kept a write from a thrown closure");
  } finally {
    await mf.dispose();
  }
});

test("workerd transaction: a committed withdrawal lands the accounting and removes pending together, and survives a restart", { timeout: 60_000 }, async () => {
  const first = await start("commit");
  try {
    const [, r] = await first.send({ method: "seed" }, { method: "withdraw", args: [false] });
    assert.equal(r, "committed");
  } finally {
    await first.mf.dispose(); // every workerd started here is stopped, pass or fail (B0 limit: bound processes)
  }
  const second = await start("commit");
  try {
    const [d] = await second.send({ method: "dump" });
    assert.deepEqual(d, { meta: { seq: 6, used: 3, bytes: 800 }, pending: null });
  } finally {
    await second.mf.dispose();
  }
});

// B2 (card 8ff5110b, BB5 b): the real Ledger in workerd admits a covered op, then withdraws a pending op
// re-timed past its run's deadline through the runtime's own transaction (AE1): number, op pool, the run's
// budget unit and the op's entry all given back together, and pending gone.
test("workerd ledger: a covered op is stored; a pending op re-timed past its run's deadline is withdrawn in one transaction", { timeout: 60_000 }, async () => {
  const { desc, opBody, runAppr, runReq } = await import("./runs.ts");
  const { sha256 } = await import("../src/contract.ts");
  const { mf, send } = await start("ledger", "ledger-harness", "LedgerBox");
  try {
    // Local R2 stamps objects with the real clock, and the run-open request and approval must be uploaded within
    // SKEW_MS of their recorded time (CC2, DD1; a fixed date here was refused as late, which proves that check
    // reads R2's own upload time), so the run opens now.
    const A = Date.now(), iso = (t: number) => new Date(t).toISOString(), MIN = 60_000, HOUR = 60 * MIN;
    const req = runReq(desc(A)), reqSha = await sha256(req);
    const out = await send(
      { method: "accept", args: [req, iso(A)] },
      { method: "accept", args: [runAppr(reqSha), iso(A + MIN)] },
      { method: "accept", args: [opBody("op-0000000001", reqSha), iso(A + 10 * MIN)] },
      { method: "failNext", args: [1] },
      { method: "accept", args: [opBody("op-0000000002", reqSha), iso(A + 4 * HOUR - MIN)] },
      { method: "read", args: [["meta", "g:runopen-0001", "o:op-0000000002", "pending"]] },
      { method: "accept", args: [JSON.stringify({ v: 1, grant: "echo-grant-01", stage: "request", job: "test.echo" }), iso(A + 4 * HOUR + 10 * MIN)] },
      { method: "read", args: [["meta", "g:runopen-0001", "o:op-0000000001", "o:op-0000000002", "pending"]] },
      { method: "listed" },
    );
    assert.deepEqual(out.slice(0, 3).map((o) => o.status), [201, 201, 201], "the run or its covered op was not stored in workerd");
    assert.equal(out[4].status, 503);
    const mid = out[5], end = out[7];
    assert.deepEqual([mid.meta.seq, mid.meta.op_used, mid["g:runopen-0001"].ops, Boolean(mid["o:op-0000000002"]), Boolean(mid.pending)], [4, 4, 2, true, true]);
    assert.equal(out[6].status, 201);
    assert.deepEqual([end.meta.seq, end.meta.op_used, end["g:runopen-0001"].ops, end["o:op-0000000002"], end.pending, end["o:op-0000000001"].state], [4, 2, 1, null, null, "open"], "workerd withdrawal did not give back the op whole");
    assert.equal(out[8].length, 4, "the bucket does not hold exactly request, approval, op and the tap request");
    assert.ok(out[8][3].endsWith(".echo-grant-01.request.json"), "the tap request did not take the withdrawn op's number");
  } finally {
    await mf.dispose();
  }
});
