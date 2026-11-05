// Test-only Worker for test/recorder.workerd.test.ts (card 8ff5110b, BB5 b): the real Ledger inside a real
// SQLite Durable Object, on Cloudflare's own ctx.storage (the same cast src/recorder/index.ts makes) and a
// local R2 bucket, so op admission and an op withdrawal run through the runtime's own transaction. The
// bucket wrapper can fail the next puts, as an outage would. Never deployed: bundled by the test into a temp
// dir and loaded into Miniflare. Commands: POST [{method, args}]; times are ISO strings.
import { DurableObject } from "cloudflare:workers";
import { Ledger, type Bucket, type Storage } from "../../src/recorder/ledger.ts";

export class LedgerBox extends DurableObject<{ RECORDS: R2Bucket }> {
  #fail = 0;
  #bucket: Bucket = {
    get: (k: string) => this.env.RECORDS.get(k),
    put: ((k: string, v: string, o?: R2PutOptions) => {
      if (this.#fail > 0) {
        this.#fail--;
        return Promise.reject(new Error("R2 down"));
      }
      return this.env.RECORDS.put(k, v, o);
    }) as Bucket["put"],
  };
  // Passkey check passes (the passkey path has its own tests); run ops on from record 1.
  #ledger = new Ledger(this.ctx.storage as unknown as Storage, this.#bucket, undefined, async () => undefined, { opsFrom: 1 });
  async accept(body: string, at: string) {
    return this.#ledger.accept(body, () => new Date(at));
  }
  failNext(n: number) {
    this.#fail = n;
  }
  async read(keys: string[]) {
    return Object.fromEntries(await Promise.all(keys.map(async (k) => [k, (await this.ctx.storage.get(k)) ?? null])));
  }
  async listed() {
    return (await this.env.RECORDS.list({ prefix: "records/" })).objects.map((o) => o.key);
  }
}

export default {
  async fetch(request: Request, env: { BOX: DurableObjectNamespace<LedgerBox> }) {
    const stub = env.BOX.get(env.BOX.idFromName("v1")) as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
    const out: unknown[] = [];
    for (const c of (await request.json()) as { method: string; args: unknown[] }[]) out.push(await stub[c.method]!(...c.args));
    return Response.json(out);
  },
};
