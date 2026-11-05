# Observatory

The studio's independent check on its agents. It will record every request agents make through the Front Desk before it runs, read what the providers say changed, and alert Ben on anything that does not match. Only code Ben approved ever runs here.

Today it does three jobs: a second, locked copy of the studio's nightly backups (phase 2c), an hourly check that what runs here is what is on `main` (card f0d4e2fc), and an hourly check of the front desk's add-only records (phase 2a, card feea07eb). A second Worker, the recorder, takes those records in (below).

## Nightly backup copy (phase 2c, card 202ac367)

At 03:15 UTC, 9:15 pm Chicago time in winter (`triggers` in `wrangler.jsonc`), `src/copy.ts` runs:

1. Lists that night's backup objects in the main backup bucket, with a read-only key scoped to that one bucket. The objects are encrypted before upload, so the Observatory cannot read them.
2. Copies each one into this account's own bucket. R2 refuses a copy whose bytes do not hash to the source's MD5, and the Worker checks the result again. A source object without a plain MD5 fails the night rather than go unchecked.
3. Tries to delete a permanently locked canary object. If it is ever gone, the lock is not working and the night fails.
4. Reads this account's own lock rules for the copy bucket (`src/lock.ts`, design 3f), because a refused delete proves a lock exists but not how long it holds. The night fails if no enabled rule covers all of `daily/` for 30 days, or any enabled rule there holds less, or the rules cannot be read or understood. Until its read-only key (`LOCK_READ_TOKEN`, `LOCK_ACCOUNT_ID`) is set at cutover, the night logs `lockLength: "not set up"` and claims nothing about it.
5. Pings the dead-man check "up" only if every step passed; otherwise it reports a failure, so Ben gets an email. A missed night also emails him.

The copy bucket's lock rules keep each night for 30 days (D2, Ben 2026-10-31; the canary forever); a lifecycle rule then removes it. Lock rules win over lifecycle rules, and the Worker's own code cannot delete a locked object. One log line per night records counts, bytes, total stored bytes, the canary result and the lock-length verdict.

## The recorder and the hourly records check (phase 2a, card feea07eb, route A)

The front desk records each grant's request, verdict, approval and result **before** it acts; the format is in `RECORDS.md`. It sends each record to the **recorder**, a separate Worker (`src/recorder/`, deployed from `wrangler.recorder.jsonc`) that reaches only the `observatory-records` bucket and its own Durable Object, never the backups. The recorder refuses, before storing anything, a record outside the contract, a stage out of order for its grant, a later stage that does not name its request's exact bytes, or a request when the day's 400 tap slots are taken or the 6 GiB lifetime storage budget is full (each request reserves its grant's other three stages for 24 hours, and those reservations carry into the next day). Run ops have their own 400-slot daily pool and stop at 5 GiB, so they can never take the room Ben's taps need (card 509a5d85); since card 8ff5110b the recorder stores an op only when Ben's passkey-approved run covers it, and one result per op (`RECORDS.md`, "Run operations"). `GET /v1/status` shows both pools, their reservations, bytes stored and pending, refusals by reason, identical retries and expired reservations. It takes records one at a time, names each with a gap-free sequence number and its own time, saves it as pending, writes it to the bucket, and only then answers with a receipt. A lock rule on `records/` makes the bucket add-only.

At :30 past every hour, as a job separate from the freshness check, `src/records.ts` re-reads every record stored since its last run, asking for each next record number by name, against the same contract (`src/contract.ts`), and reports anything the recorder should have refused or that something else wrote: a gap in the numbers, a duplicate or out-of-order stage, a broken envelope or body, an object outside the record format, more than a day's cap, and a lock on `records/` shorter than 400 days. Once a day (04:30 UTC) it lists every record name up to the bookmark and reads any number holding more than one object, naming each extra object the same way the hourly read does. Findings never repeat writer-chosen text (grant ids and stray names appear as fingerprints), and a lock it cannot read, including before `LOCK_READ_TOKEN` exists, is a finding. Since card af0e4a2f, this job's own check (`PING_URL_RECORDS`) is a light that means only "the checker ran and read what it should": green after every such run, red when a run could not finish (including a daily count that could not read an object or finish listing), and healthchecks' own alarm when a run is missed; it never means the records are fine. Every finding is an incident on a standing list with an id tied to the exact object; each record number a run could not read is one too. At most one alert a run, through Pushover; if Pushover fails it goes to the same check's `/fail`, which emails only when the check changes state, so a run that read everything pings green first and green again after, and on a run that could not finish only Pushover counts as delivered. An incident stays listed while it is still found and alerts again only if it comes back. An incident about a locked record (a planted object, a broken record) stays listed for good; one the hourly run recomputes (the lock, a gap, an unreadable number, a stray outside `records/v1/`) leaves when a full run no longer finds it. Nobody can mark one seen. The list holds 200; past that one counted line stands for the rest and alerts whenever another joins them. It remembers up to 5,000 of those; past that it says it can no longer tell new ones apart, once. A crowded record number the day's read window skips keeps its open problem until a later window reads it. Every Monday at 14:00 UTC one line says how many are open and the worst. State lives at `state/records.json` in the copy bucket. The recorder signs every envelope (Ed25519, with a key made inside its Durable Object); once Ben pins its public key (`PIN` in `src/records.ts`), a record is the one copy at its number the recorder signed, anything else there is a foreign finding, and the bookmark never passes a number without exactly one signed copy. The checker needs no step from Ben for a shared number; the recorder does not stop either, and writes beside anything planted under its next number (under a random-tagged name if its exact name was taken). Until `PING_URL_RECORDS` is set it only logs. It reads; it never writes to the records bucket.

## Hourly freshness check (card f0d4e2fc)

At :30 past every hour, `src/fresh.ts` (and only it: `src/index.ts` routes each cron by name) reads `main`'s head commit from GitHub's public API by the repo's numeric id (it survives the move to a new org), without a credential, and compares it with `DEPLOYED_SHA`, which the deploy command records for each deploy.

- `main` ahead of what is live for 6 hours: one alert ("a merge did not go live").
- GitHub unreadable for 3 hours (including its 60-an-hour limit on reads without a key), or no `DEPLOYED_SHA`, or its own state unreadable: one alert ("cannot verify what is live"). Never "healthy".
- Its own healthchecks check (`PING_URL_FRESH`) hears "up" every hour while nothing is overdue and `/fail` every hour while something is. An alert that cannot reach the phone falls back to that check, never the backup check, so a good backup night never clears a freshness failure.
- State (when a mismatch was first seen, which alert was sent) lives at `state/freshness.json` in the copy bucket; `state/` has no lock.
- Until `PING_URL_FRESH` and the `DEPLOYED_SHA` deploy command are set up at cutover, it logs one line an hour and sends nothing.

Limit: it runs inside the thing it checks. That counts only after cutover, when nothing but Workers Builds can deploy.

## When a records incident fires

Steps marked FROM MEMORY name Cloudflare dashboard places not checked against the live dashboard.

1. Read the alert: it names a record number and a fingerprint, never anything the writer chose. A planted object stays on the list for 400 days (the lock keeps it); that is expected and needs no clearing.
2. Who can write the records bucket: the recorder Worker (through its binding, no token), any Cloudflare API token on the Observatory account with R2 write (during the build, the temporary setup key until 2026-11-13), and the account's owner login. Nothing else.
3. Which one wrote it: compare the object's upload time (R2, the records bucket, the object list; FROM MEMORY) with when each R2-write token existed and was last used (the account's API tokens page; FROM MEMORY). Cloudflare's audit log records token changes, not single object writes (FROM MEMORY).
4. Cut it off: roll or delete every R2-write token on the Observatory account (the recorder needs none). If the owner login is in doubt, change its password and check its 2FA.
5. `forged` (two copies carry the recorder's signature) means the recorder's key may be stolen: ask an agent for a new-key card. `missing` (a record gone below the bookmark) means the lock did not hold: check the lock rule first.

## How it is protected

- **Who can change it:** `main` takes only pull requests with Ben's approval of the latest push (ruleset `protect-main`, the same as front-desk's): no bypass, no force push, no deletion.
- **Its own home (moved 2026-10-31, card 3e2f8870):** this repo lives in its own GitHub org, `weird-ways-observatory`, owned by `benculbert` and `weird-ways`, which refuses all personal access tokens, so no agent credential can reach it (proof 5.7.4: agent writes refused). Agents propose changes from a fork, `weird-ways-studio/observatory-proposals`, and send Ben a compare link (see `CLAUDE.md`). The rest of the cutover (revoking the construction keys, new secrets, proofs) is still open on that card.
- **What deploys:** Cloudflare **Workers Builds** in the Observatory's own Cloudflare account builds `main` and deploys it; its trigger includes only `main`, because a branch build would run code nobody reviewed with the build's deploy rights. A merge starts the build by itself (proven 2026-11-01, PR #10; root-cause card c19f4946).
- **Who holds keys:** no agent holds any Observatory credential, except two temporary keys Ben approved for phase 2c setup (one for R2 and Workers scripts, one for reading and starting builds), both expiring 2026-11-13. Agents change the code only by opening pull requests.
- **Address (studio app-exposure doors), backup Worker:** none. `wrangler.jsonc` turns off workers.dev and preview URLs and has no routes, so the Worker is unreachable from any network, which is stricter than the tailnet-only door. `test/config.test.ts` fails if the address, bindings or schedules change.
- **Address, recorder Worker: door 2** (edge login in front of the whole Worker). Its one address is its workers.dev URL, behind Cloudflare Access, which admits only the front desk's service token and Ben. Why not door 1: the front desk runs on Cloudflare, not on the tailnet, so it cannot reach a tailnet-only address. Ben chose this route on 2026-11-01 (Brain task 56d8dd39, after a cross-model review). The Worker also checks Access's signed token itself (`src/recorder/access.ts`: signature, issuer, audience, expiry, identity) and refuses everything while its settings are missing, so a wrong Access setting alone never opens it. Answers carry `X-Robots-Tag: noindex`. `test/recorder-config.test.ts` fails if its address or bindings change.
- **Entry points:** `src/index.ts` (`main` in `wrangler.jsonc`); Cloudflare calls its default export's `scheduled` on each cron and `fetch` only if an address were ever added. The recorder: `src/recorder/index.ts` (`main` in `wrangler.recorder.jsonc`); Cloudflare calls `fetch` for each request (`src/recorder/http.ts` routes it) and runs the `Recorder` Durable Object class, named in the config's `durable_objects` binding, as one instance named "v1".

## Turning run ops off (card 8ff5110b)

`OPS_ENABLED` in `src/recorder/ledger.ts` is the off switch. A one-line PR setting it to `false` (Ben merges) makes the recorder refuse every new op (403, counted as `switched_off`) while results, pending writes and Ben's taps go on. **Once the recorder has admitted a run-open request, use the switch, never a revert:** older code does not know the run and op state. `GET /v1/status` shows `ops.runs_admitted`; while it is 0 a revert is still safe. The front desk sends no run-open request until build 4a-3.

## Known limits

- Until the studio's temporary access ends on 2026-11-13 (revocation plan, epic cafd3acc), agents hold keys that can edit org rulesets, the main backup bucket's settings, and this account. So neither this protection nor the backup copy is independent of the agents yet; independence is claimed only after those keys are proven refused.
- The copy faithfully copies whatever the source holds. If tonight's source were overwritten with garbage, earlier nights stay locked here for 30 days; spotting the tampering is a later phase.
- Cloudflare's own GitHub app (Workers and Pages) holds administration write on the repos it is installed on. Cloudflare controls it; no studio agent can drive it.

- The recorder is live since 2026-11-01 (card feea07eb): Access in front with the front desk's service token, the records bucket under its lock, and its own Workers Builds connection. Refusals were proven live then (a stranger, a forged token and a wrong secret refused); the service token's admission is proven by the front desk's first real record (phase 3, card 97a2e83d).
- The recorder and the front desk agree on order, not on truth: a tampered front-desk deploy could skip recording. Phase 3 makes the front desk refuse to run without a receipt; Ben's review of `main` remains the control.
- The service token's identity is read from the token's `common_name` claim (FROM MEMORY of Access's service-token tokens; the sitting's live proof confirms it).

## Develop

`npm test`, `npm run typecheck`. Install packages only inside the studio sandbox.
