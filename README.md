# pi-web-fetch

> **Distribution mirror.** Developed in a private source-of-truth repo and synced here for distribution
> (current sync: `pi_config@d653613`, 2026-06-12). The `main` branch is force-synced — please don't
> target PRs at it directly; file an [issue](https://github.com/psmfd/pi-web-fetch/issues)
> instead and fixes will land via the next sync.

Pi extension that registers `web_fetch(url, accept?)`: an HTTPS GET against an operator-curated allowlist of first-party documentation hosts, returning the response body (≤256 KB). Read-only, credential-free, no search, no browser. Built so agents corroborate claims against authoritative documentation instead of citing from cached model knowledge.

## Install

```bash
pi install git:github.com/psmfd/pi-web-fetch@v0.1.0
```

Or try it for a single session without installing:

```bash
pi -e git:github.com/psmfd/pi-web-fetch
```

No build step — pi loads the TypeScript directly. The pi SDK and `typebox` are bundled by pi itself; this extension has no runtime dependencies of its own.

## Security boundary

The single security boundary is the **host allowlist** in `index.ts` (the `ALLOWED_HOSTS` set — ~60 first-party documentation hosts: vendor docs, language references, standards bodies, man pages). The threat model assumes:

- The agent's reasoning can be steered by adversarial content in any file or tool output it reads (prompt injection).
- An attacker who can steer reasoning will try to drive the agent to fetch arbitrary URLs (SSRF, data exfiltration to attacker-controlled hosts, credential probing of internal endpoints).
- The defense is operator-curated host selection at allowlist-edit time: an attacker cannot add a host without a reviewed change to `index.ts`.

This is a defense-in-depth posture, not perimeter security. Subordinate enforcement:

| Rule | Enforcement |
|---|---|
| URL scheme must be `https:` | Hard refusal — refuses `http:`, `file:`, `data:`, anything else |
| URL host must be in `ALLOWED_HOSTS` | Hard refusal |
| 3xx redirects must each land on an allowlisted host | Hard refusal at the offending hop; max 3 hops total. Defeats open-redirector bypass on otherwise-allowlisted hosts. |
| Response body >256 KB | Truncated to 256 KB (not refused); truncation is reported in the tool result `details` |
| Non-2xx terminal response | Returned as tool error with status code |

No `SKIP_*` env override exists. Adding a host means editing `ALLOWED_HOSTS` in your copy (and the coverage rationale below applies — keep it first-party).

## Refusal policy (per-rule)

| Rule | Mode |
|---|---|
| Input URL fails to parse | Hard refusal |
| Non-`https:` scheme | Hard refusal |
| Host not on allowlist | Hard refusal |
| Redirect to non-allowlisted host | Hard refusal |
| Redirect to non-`https:` URL | Hard refusal |
| Redirect 3xx with missing or unparseable `Location` header | Hard refusal |
| Redirect chain longer than 3 hops | Hard refusal |
| Non-2xx terminal response | Hard refusal (surfaced with HTTP status) |
| Body exceeds 256 KB | Continue-eligible (truncate + report in `details.truncated`) |
| Response advertises `Content-Length` > 2 MB (8× cap) | Hard refusal — defense-in-depth against runaway allocations |
| Response body exceeds 2 MB mid-stream (no Content-Length or server lied) | Hard refusal at the streaming-read layer |
| Network error (DNS, connect, TLS) | Hard refusal (surfaced with error message) |

## Allowlist curation

The full list lives in `index.ts` `ALLOWED_HOSTS`, alphabetized, with one entry per host (no wildcards). The curation test for adding a host: is this a first-party documentation host? Does it serve user-generated content as a *primary* surface? If user content is incidental (e.g. comments on an official doc page), the host is acceptable; if it's primary (a forum, Stack Overflow, Medium), it is not.

Three allowlisted hosts — `github.com` (+ `raw.githubusercontent.com`), `huggingface.co`, and `ollama.com` — carry a documented trade-off: their curated documentation surfaces coexist with arbitrary user-published content. They are accepted because the agent already reads user-influenceable content via `read` and tool outputs, so host-level allowlisting of these does not materially expand the prompt-injection-driven SSRF surface the allowlist is designed to bound. The redirect re-validation loop still defeats open-redirector escapes from these hosts (e.g. an LFS link that 302s to a CDN host is hard-refused at the hop). Path-prefix matching is the documented upgrade path if abuse surfaces.

## What this extension explicitly does NOT do

- **No search.** There is no `web_search` tool. Agents must know the URL or follow links inside fetched documents. Adding search erodes the allowlist (attacker-influenced URL discovery) and exfiltrates queries to a third-party provider — deliberate scope boundary.
- **No browser automation.** Static `fetch` only — no JavaScript execution, no DOM, no cookies, no session state.
- **No authenticated fetches.** No credentials are read, stored, or sent.
- **No `http:`, `file:`, or `data:` URLs.** HTTPS only.

## Smoke test

```bash
pi --tools web_fetch -p \
  "Use web_fetch to retrieve https://www.gnu.org/software/bash/manual/bash.html and quote the exact wording of how 'set -e' interacts with command substitution."
```

Expected: the agent invokes `web_fetch` once, the tool result includes `200` and an HTML fragment from gnu.org, and the response quotes the manual rather than reciting from cached knowledge.

Refusal smoke:

```bash
pi --tools web_fetch -p "Fetch https://example.com/"
```

Expected: tool result `web_fetch: refusing 'https://example.com/' — host 'example.com' is not on the first-party-docs allowlist. …`

## Development

```bash
npm install
npm run typecheck
```

## License

[MIT](LICENSE)
