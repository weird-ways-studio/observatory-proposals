// Self-tests for the mutation harness (scripts/mutants.mjs, card 0d001fc3): it must count a mutant as caught
// only for a genuine assertion failure of the one named test, and fail the run for every other outcome.
// Each case runs the real command against the fixture project in test/fixtures/mutants.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";

const run = (...args: string[]) => runIn("test/fixtures/mutants", ...args);
const runIn = (root: string, ...args: string[]) => {
  // Always as if under a parent test runner (node sets NODE_TEST_CONTEXT there), so the harness's handling of it
  // is exercised the same way under npm test and under the harness's own in-process runs.
  const env = { ...process.env, NODE_TEST_CONTEXT: "child-v8" };
  const r = spawnSync(process.execPath, ["scripts/mutants.mjs", "--root", root, "--modules", `${process.cwd()}/node_modules`, "--timeout", "4000", ...args], { encoding: "utf8", env, timeout: 300_000, killSignal: "SIGKILL" });
  return { code: r.status, out: r.stdout + r.stderr };
};
const one = (id: string) => run("--only", id);

describe("mutation harness", { concurrency: true }, () => {
  const cases: [string, number, RegExp][] = [
    ["kill", 0, /^CAUGHT kill \[self\]: "clamp caps at max" failed: clamp-cap$/m],
    ["survivor", 1, /^SURVIVED survivor .*still passes$/m],
    ["missing-anchor", 1, /^INVALID missing-anchor .*anchor occurs 0 times/m],
    ["duplicate-anchor", 1, /^INVALID duplicate-anchor .*anchor occurs 3 times/m],
    ["compile-error", 1, /^INVALID compile-error .*does not typecheck: .*TS2322/m],
    ["runtime-throw", 1, /^INVALID runtime-throw .*failed with TypeError, not an assertion: boom$/m],
    ["module-load", 1, /^INVALID module-load .*: 0 tests named "clamp caps at max" ran in test\/lib\.test\.ts$/m],
    // B1 retro L3: a test leaves a process running; the harness finds it in the run's process group and kills it.
    ["orphan", 1, /^INVALID orphan .*: test process\(es\) outlived the run and were killed$/m],
    // On this node the spinning test dies with its runner; if it ever outlives it, the line says so too.
    ["timeout", 1, /^INVALID timeout .*timeout after 4000 ms(; test process\(es\) outlived the run and were killed)?$/m],
    ["zero-tests", 1, /^INVALID zero-tests .*baseline: 0 tests named "clamp caps" ran in test\/lib\.test\.ts$/m],
    ["wrong-message", 1, /^INVALID wrong-message .*does not contain "some-other-message"/m],
    ["baseline-fails", 1, /^INVALID baseline-fails .*baseline: designated test fails unmutated \(broken-baseline\)$/m],
    // Codex B0 r1 regressions: each of these printed CAUGHT before the fix.
    ["hook-only", 1, /^INVALID hook-only .*failed in hookFailed, not in the test's own body$/m],
    ["skipped-baseline", 1, /^INVALID skipped-baseline .*baseline: "target" was skipped, not run$/m],
    ["suite-hook", 1, /^INVALID suite-hook .*other suite "grp" finished \(hookFailed\)$/m],
    ["imported-test", 1, /^INVALID imported-test .*other test "clamp caps at max" in lib\.test\.ts finished \(pass\)$/m],
    ["self-kill", 1, /^INVALID self-kill .*killed by SIGKILL$/m],
    ["escape-path", 1, /^INVALID escape-path .*mutated file is outside the project or in node_modules$/m],
    ["nested-kill", 0, /^CAUGHT nested-kill \[self\]: "target" failed: clamp-cap$/m],
    ["late-module-load", 1, /^INVALID late-module-load .*baseline: 0 tests named "target" ran in test\/lateload\.test\.ts$/m],
    ["self-term", 1, /^INVALID self-term .*killed by SIGTERM$/m],
    ["self-int", 1, /^INVALID self-int .*killed by SIGINT$/m],
    ["noisy-stdout", 0, /^CAUGHT noisy-stdout \[self\]: "target" failed: clamp-cap$/m],
    // Codex B0 r3: a stated limit, not a gap -- the kill is genuine; the later module error is not seen.
    ["async-late", 0, /^CAUGHT async-late \[self\]: "target" failed: clamp-cap$/m],
  ];
  for (const [id, code, line] of cases)
    test(`fixture mutant ${id}`, () => {
      const r = one(id);
      assert.match(r.out, line, `fixture ${id} output: ${r.out}`);
      assert.equal(r.code, code, `fixture ${id} exit code: ${r.out}`);
    });

  test("a whole run fails when any mutant is not caught, and lists retired entries", () => {
    const r = run();
    assert.match(r.out, /^4\/24 caught; 20 not caught -- run FAILS$/m, r.out);
    assert.match(r.out, /^RETIRED old: fixture: shows a retired entry is listed$/m, r.out);
    assert.equal(r.code, 1);
  });

  test("a project holding a symlink is refused, and the file it points at is never written", () => {
    const root = mkdtempSync(join(tmpdir(), "mutants-selftest-")), away = mkdtempSync(join(tmpdir(), "mutants-away-"));
    try {
      cpSync("test/fixtures/mutants", root, { recursive: true });
      const target = join(away, "outside.ts"), text = "export const v = 1;\n";
      writeFileSync(target, text);
      symlinkSync(target, join(root, "src", "link.ts"));
      const list = { mutants: [{ id: "via-link", row: "self", file: "src/link.ts", find: "v = 1", replace: "v = 2", why: "write through a symlink", test: { file: "test/lib.test.ts", name: "clamp caps at max" }, expect: "clamp-cap" }] };
      writeFileSync(join(root, "symlink-list.json"), JSON.stringify(list));
      const r = runIn(root, "--list", "symlink-list.json");
      assert.match(r.out, /^INVALID via-link \[self\]: project holds a symlink \(src\/link\.ts\)$/m, `symlink output: ${r.out}`);
      assert.equal(r.code, 1);
      assert.equal(readFileSync(target, "utf8"), text, "the file behind the symlink is unchanged");
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(away, { recursive: true, force: true });
    }
  });

  test("an id that selects nothing fails the run", () => {
    const r = one("no-such-mutant");
    assert.match(r.out, /^INVALID no mutants selected \(--only no-such-mutant\)$/m, r.out);
    assert.equal(r.code, 1);
  });
});
