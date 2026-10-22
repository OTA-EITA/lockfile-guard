import type { Packument, Registry } from "./registry.js";

export interface HttpRegistryOptions {
  /** Registry base URL, e.g. https://registry.npmjs.org. */
  url: string;
  /** Bearer token for private registries. */
  token?: string;
  retries?: number;
  timeoutMs?: number;
}

/** Reads package documents from an npm-compatible registry over HTTPS. */
export class HttpRegistry implements Registry {
  private readonly base: string;

  constructor(private readonly opt: HttpRegistryOptions) {
    this.base = opt.url.replace(/\/+$/, "");
  }

  async packument(name: string): Promise<Packument | null> {
    // Scoped names keep the "@" and escape the slash: @scope%2fname.
    const url = `${this.base}/${name.startsWith("@") ? "@" + encodeURIComponent(name.slice(1)) : encodeURIComponent(name)}`;
    const headers: Record<string, string> = { accept: "application/json" };
    if (this.opt.token) headers.authorization = `Bearer ${this.opt.token}`;
    const retries = this.opt.retries ?? 2;
    for (let attempt = 0; ; attempt++) {
      const res = await fetch(url, { headers, signal: AbortSignal.timeout(this.opt.timeoutMs ?? 30_000) });
      if (res.status === 404) return null;
      if ((res.status === 429 || res.status >= 500) && attempt < retries) {
        await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
        continue;
      }
      if (!res.ok) throw new Error(`GET ${url}: HTTP ${String(res.status)}`);
      const body = (await res.json()) as Partial<Packument>;
      return { time: body.time ?? {}, versions: body.versions ?? {} };
    }
  }
}
