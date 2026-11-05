// Mutation harness (card 0d001fc3; studio-os REFINE-observatory-ops.md Z2). Each mutant in the list removes
// or weakens one named safeguard and names the ONE test that must catch it, with the assertion message that
// test must fail with. A mutant counts as CAUGHT only when all of these hold:
//   1. the copy holds no symlink, and the mutated file and test file lie inside it (never node_modules);
//   2. its `find` text occurs exactly once in its file;
//   3. on that fresh copy, the unmutated designated test runs alone, not skipped, and passes, and the run
//      exits 0 (per-mutant baseline);
//   4. the mutated copy passes tsc;
//   5. exactly the designated test (that name, defined in that file) ran, not skipped, and its own body failed
//      (failureType testCodeFailure, not a hook) with an AssertionError whose message contains `expect`; no
//      suite failed except because of it; and the run exited 1 without a signal.
// The test file runs directly (`node FILE`, node:test running in that one process, no --test runner): a module
// that throws while it loads, even after registering tests, exits non-zero with no events; a kill, SIGTERM or
// SIGINT ends the process and is seen as a signal; no test worker exists to outlive a timeout (Codex B0 r1 #3, #6;
// r2). Limits, by design (Codex B0 r3): an error the module throws after an awaited test has already reported is
// not seen -- the kill still stands, since that test's own assertion failed; and tests that start their own
// processes must bound them themselves (test/mutants.test.ts does).
// Anything else -- missing or duplicate anchor, compile error, a non-assertion throw, a hook failure, a skip,
// a module that fails to load, a signal, a timeout, zero or extra tests -- FAILS the run as INVALID, and a test
// that still passes is SURVIVED. The run exits 0 only when every listed mutant is CAUGHT.
//
// Usage: node scripts/mutants.mjs [--root DIR] [--list FILE] [--modules DIR] [--timeout MS] [--only ID]
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const REPORTER = fileURLToPath(new URL("./mutants-reporter.mjs", import.meta.url));
const SKIP = new Set([".git", "node_modules", ".wrangler"]);

/** Reads the command-line options; paths resolve against --root (default: the current directory). */
export function parseArgs(argv) {
  const o = { root: process.cwd(), list: undefined, modules: undefined, timeout: 60_000, only: undefined };
  for (let i = 0; i < argv.length; i += 2) {
    const [k, v] = [argv[i], argv[i + 1]];
    if (v === undefined || !["--root", "--list", "--modules", "--timeout", "--only"].includes(k)) throw new Error(`bad argument ${k}`);
    o[k.slice(2)] = k === "--timeout" ? Number(v) : v;
  }
  o.root = resolve(o.root);
  o.list = resolve(o.root, o.list ?? "test/mutants.json");
  o.modules = resolve(o.root, o.modules ?? "node_modules");
  return o;
}

/** Throws unless every mutant has every field and ids are unique; returns the parsed list. */
export function loadList(path) {
  const list = JSON.parse(readFileSync(path, "utf8"));
  const ids = new Set();
  for (const m of [...list.mutants, ...(list.retired ?? [])]) {
    if (typeof m.id !== "string" || ids.has(m.id)) throw new Error(`missing or duplicate mutant id ${m.id}`);
    ids.add(m.id);
  }
  for (const m of list.mutants)
    for (const f of ["row", "file", "find", "replace", "why", "expect"])
      if (typeof m[f] !== "string" || (f !== "replace" && m[f] === "")) throw new Error(`mutant ${m.id}: ${f} missing`);
  for (const m of list.mutants)
    if (typeof m.test?.file !== "string" || typeof m.test?.name !== "string") throw new Error(`mutant ${m.id}: test missing`);
  for (const r of list.retired ?? []) if (typeof r.reason !== "string" || !r.reason) throw new Error(`retired ${r.id}: reason missing`);
  return list;
}

/** A throwaway copy of the project (no .git, no build output) with the real packages linked in. Refuses a
 *  project holding any symlink: copied, it would still point at the original files (Codex B0 r1 #5). */
function freshCopy(o) {
  const dir = mkdtempSync(join(tmpdir(), "mutant-"));
  cpSync(o.root, dir, { recursive: true, filter: (src) => !SKIP.has(basename(src)) });
  const link = readdirSync(dir, { recursive: true, withFileTypes: true }).find((d) => d.isSymbolicLink());
  if (link) return { dir, why: `project holds a symlink (${relative(dir, join(link.parentPath, link.name))})` };
  symlinkSync(o.modules, join(dir, "node_modules"), "dir");
  return { dir };
}

/** The path of a project file inside the copy, or undefined when it would leave the copy or enter node_modules. */
function inside(dir, file) {
  const abs = resolve(dir, file), rel = relative(dir, abs);
  return rel && !rel.startsWith("..") && !rel.startsWith(sep) && rel.split(sep)[0] !== "node_modules" ? abs : undefined;
}

/** Escapes a test name so --test-name-pattern matches it literally. */
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * True if any process of the group led by `pid` is still alive. Each test run is started as its own process
 * group (setsid), so a test process node --test started in a child of its own, which the runner's SIGKILL does
 * not reach, is still found: 26 such "spin ends" loops held the c-box at full CPU for 8.5 h after B1 (retro
 * 8722b770 L3). Kills what it finds.
 */
export function reap(pid) {
  try {
    process.kill(-pid, 0);
  } catch {
    return false; // ESRCH: nothing of the group is left
  }
  try { process.kill(-pid, "SIGKILL"); } catch { /* went in between */ }
  return true;
}

/** Runs one named test alone; returns the finished-test events and exit status, or why the run went wrong. */
function runTest(dir, test, timeout) {
  // Under a parent test runner node sets NODE_TEST_CONTEXT, and a child run then reports to that parent
  // instead of our reporter (seen as "0 tests ran"); the child must run as a top-level test run.
  const { NODE_TEST_CONTEXT: _, ...env } = process.env;
  // The reporter writes to its own file: the code under test shares stdout (records.ts logs JSON lines).
  const out = join(dir, ".mutants-events.jsonl");
  rmSync(out, { force: true });
  const args = [`--test-reporter=${REPORTER}`, `--test-reporter-destination=${out}`, `--test-name-pattern=^${escape(test.name)}$`, test.file];
  // setsid (util-linux) makes node the leader of a new process group without forking, so r.pid is the group.
  const r = spawnSync("setsid", [process.execPath, ...args], {
    cwd: dir, env, encoding: "utf8", timeout, killSignal: "SIGKILL",
  });
  if (r.error && r.error.code !== "ETIMEDOUT") return { why: `could not start the test run: ${r.error.code}` };
  // Anything of this run still alive is killed and makes the mutant INVALID, so the whole run fails (L3).
  const orphans = r.pid && reap(r.pid) ? "; test process(es) outlived the run and were killed" : "";
  if (r.error?.code === "ETIMEDOUT") return { why: `timeout after ${timeout} ms${orphans}` };
  if (orphans) return { why: orphans.slice(2) };
  if (r.signal) return { why: `killed by ${r.signal}` };
  const events = existsSync(out) ? readFileSync(out, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  return { events, status: r.status };
}

/** Exactly the designated test (that name, defined in that file) finished, once, not skipped, and nothing else
 *  did. A suite may finish too, but only passing or failed because of its subtests (Codex B0 r1 #1-#4). */
function only(events, test, file) {
  const mine = events.filter((e) => e.type === "test" && e.name === test.name && e.file === file);
  const other = events.filter((e) => !mine.includes(e) && !(e.type === "suite" && (e.ok || e.failureType === "subtestsFailed")));
  if (other.length) {
    const x = other[0], where = x.file === file ? "" : ` in ${x.file ? relative(resolve(file, ".."), x.file) : "no file"}`;
    return { why: `other ${x.type ?? "event"} ${JSON.stringify(x.name)}${where} finished (${x.ok ? "pass" : x.failureType ?? "fail"})` };
  }
  if (mine.length !== 1) return { why: `${mine.length} tests named ${JSON.stringify(test.name)} ran in ${test.file}` };
  if (mine[0].skip || mine[0].todo) return { why: `${JSON.stringify(test.name)} was ${mine[0].skip ? "skipped" : "todo"}, not run` };
  return { event: mine[0] };
}

/** One mutant's outcome: { verdict: "CAUGHT" | "SURVIVED" | "INVALID", why }. */
export function runMutant(o, m) {
  const { dir, why } = freshCopy(o);
  try {
    if (why) return { verdict: "INVALID", why };
    const path = inside(dir, m.file), file = inside(dir, m.test.file);
    if (!path || !file) return { verdict: "INVALID", why: `${path ? "test file" : "mutated file"} is outside the project or in node_modules` };
    const src = readFileSync(path, "utf8");
    const count = src.split(m.find).length - 1;
    if (count !== 1) return { verdict: "INVALID", why: `anchor occurs ${count} times in ${m.file}` };
    const base = runTest(dir, m.test, o.timeout);
    if (base.why) return { verdict: "INVALID", why: `baseline: ${base.why}` };
    const b = only(base.events, m.test, file);
    if (b.why) return { verdict: "INVALID", why: `baseline: ${b.why}` };
    if (!b.event.ok) return { verdict: "INVALID", why: `baseline: designated test fails unmutated (${b.event.error?.message?.split("\n")[0]})` };
    if (base.status !== 0) return { verdict: "INVALID", why: `baseline: run exited ${base.status}` };
    writeFileSync(path, src.replace(m.find, () => m.replace));
    const tsc = spawnSync(join(o.modules, ".bin", "tsc"), ["-p", join(dir, "tsconfig.json")], { cwd: dir, encoding: "utf8", timeout: o.timeout });
    if (tsc.status !== 0) return { verdict: "INVALID", why: `mutant does not typecheck: ${(tsc.stdout + tsc.stderr).trim().split("\n")[0]}` };
    const run = runTest(dir, m.test, o.timeout);
    if (run.why) return { verdict: "INVALID", why: run.why };
    const t = only(run.events, m.test, file);
    if (t.why) return { verdict: "INVALID", why: t.why };
    if (t.event.ok) return run.status === 0 ? { verdict: "SURVIVED", why: `${JSON.stringify(m.test.name)} still passes` } : { verdict: "INVALID", why: `run exited ${run.status}` };
    if (run.status !== 1) return { verdict: "INVALID", why: `run exited ${run.status}, not 1` };
    if (t.event.failureType !== "testCodeFailure") return { verdict: "INVALID", why: `failed in ${t.event.failureType ?? "an unknown place"}, not in the test's own body` };
    const e = t.event.error;
    if (e?.name !== "AssertionError" || e?.code !== "ERR_ASSERTION") return { verdict: "INVALID", why: `failed with ${e?.name ?? "no error"}, not an assertion: ${e?.message?.split("\n")[0]}` };
    if (!e.message.includes(m.expect)) return { verdict: "INVALID", why: `assertion message does not contain ${JSON.stringify(m.expect)}: ${e.message.split("\n")[0]}` };
    return { verdict: "CAUGHT", why: `${JSON.stringify(m.test.name)} failed: ${e.message.split("\n")[0]}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Runs the selected mutants, prints one line each, and returns the exit code (0 only if all are caught). */
export function main(argv) {
  const o = parseArgs(argv);
  const list = loadList(o.list);
  const todo = list.mutants.filter((m) => o.only === undefined || m.id === o.only);
  if (!todo.length) { console.log(`INVALID no mutants selected${o.only ? ` (--only ${o.only})` : ""}`); return 1; }
  let bad = 0;
  const notCaught = [];
  for (const m of todo) {
    const r = runMutant(o, m);
    if (r.verdict !== "CAUGHT") { bad++; notCaught.push(m.id); }
    console.log(`${r.verdict} ${m.id} [${m.row}]: ${r.why}`);
  }
  if (o.only === undefined) for (const r of list.retired ?? []) console.log(`RETIRED ${r.id}: ${r.reason}`);
  // Every non-CAUGHT id again on one line at the end, so a cut-off log still names them (B1 retro L3).
  if (bad) console.log(`NOT CAUGHT: ${notCaught.join(" ")}`);
  console.log(`${todo.length - bad}/${todo.length} caught${bad ? `; ${bad} not caught -- run FAILS` : ""}`);
  return bad ? 1 : 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2));
