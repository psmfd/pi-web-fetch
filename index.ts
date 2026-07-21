/**
 * web-fetch — pi extension
 *
 * Registers the `web_fetch` tool used by research-specialist subagents
 * (security-review-expert, code-review-expert, shell-expert, aws-expert,
 * azure-infra-expert, azure-devops-expert, dotnet-expert, docker-expert,
 * helm-expert, tauri-expert, ansible-expert, hyperv-expert, wsl2-expert,
 * vcluster-expert, pi-agent-expert, docs-expert, checkmarx-expert,
 * gh-cli-expert, gitflow-expert, linter) to fetch first-party
 * documentation and corroborate findings against authoritative sources.
 *
 * Security boundary: a tight, operator-curated allowlist of first-party
 * documentation hosts. Anything not on the allowlist is refused. Adding a
 * host requires a PR and is the policy surface for prompt-injection-driven
 * SSRF defense. See README.md and ADR-0015.
 *
 * Refusal rules (all hard refusals; no override mechanism in v1):
 *   - URL scheme must be `https:` (refuses `http:`, `file:`, `data:`, …)
 *   - URL host must be in ALLOWED_HOSTS
 *   - 3xx redirects are resolved manually; each hop's host must also be in
 *     ALLOWED_HOSTS (max 3 hops) — defeats open-redirect bypass on hosts
 *     that allowlist a redirector parameter
 *   - non-2xx terminal responses surface as tool errors
 *
 * Truncation: response body is read in full and truncated to
 * MAX_BODY_BYTES (256 KB) per #151 acceptance criteria. The pi runtime
 * handles any further downstream truncation when surfacing to the model.
 *
 * Secrets-guard interaction: `web_fetch` is read-only (does not write to
 * disk or commit anything). No secrets-guard coverage needed; this tool
 * cannot exfiltrate by writing — only by surfacing remote content to the
 * model, which is bounded by the host allowlist.
 *
 * Source rules: see README.md. Tracking issue: #151. ADR-0015.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

export const MAX_BODY_BYTES = 262144; // 256 KB
// Defense-in-depth ceiling (8× the truncation cap): the largest response body
// web_fetch will buffer before refusing. Bounds memory pressure from a
// misbehaving or compromised allowlisted host (Content-Length pre-check +
// mid-stream streaming guard, both in readBodyBounded).
export const HARD_BYTE_CEILING = MAX_BODY_BYTES * 8; // 2 MB
const MAX_REDIRECTS = 3;
const DEFAULT_ACCEPT = "text/html,text/plain,application/xhtml+xml,*/*;q=0.8";
const USER_AGENT = "pi-web-fetch/1.0 (+https://github.com/psmfd/pi-web-fetch)";

/**
 * First-party documentation hosts. Alphabetized for diff-friendliness.
 * Adding a host is a deliberate PR — see README.md § Adding a host.
 *
 * Coverage matrix is tracked in README.md § Allowlist.
 *
 * Note: allowlist check uses `URL.host` (not `URL.hostname`) so a redirect
 * to `<allowed-host>:8443` is refused — the default `:443` is stripped by
 * the URL parser, so canonical entries (no port) match as expected.
 */
export const ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  // ADR (MADR template — adr-required rule)
  "adr.github.io",
  // Ansible
  "docs.ansible.com",
  // Anthropic (Claude Code installer + model docs; mid-migration from
  // docs.anthropic.com to docs.claude.com — both hosts kept live during the
  // transition. See #222.)
  "docs.anthropic.com",
  "docs.claude.com",
  // Apple
  "developer.apple.com",
  // Astral (Ruff linter + uv package manager)
  "docs.astral.sh",
  // AWS
  "docs.aws.amazon.com",
  // AWS re:Post (vendor-operated Q&A forum; replaces AWS Developer Forums)
  "repost.aws",
  // Checkmarx (SAST/SCA/IaC scanner; checkmarx-expert)
  "docs.checkmarx.com",
  // Conventional Commits (spec referenced by conventional-commits rule)
  "www.conventionalcommits.org",
  // CVE (MITRE-operated CVE catalog; security-review-expert)
  "www.cve.org",
  // Docker
  "docs.docker.com",
  // .NET (release/SDK/lifecycle metadata; prose docs live on learn.microsoft.com)
  "dotnet.microsoft.com",
  // ESLint (rule reference + flat-config docs; linter and TS extension tooling)
  "eslint.org",
  // freedesktop
  "freedesktop.org",
  "specifications.freedesktop.org",
  "www.freedesktop.org",
  // Git (canonical git/git-config docs; gitflow-expert)
  "git-scm.com",
  // GitHub (broad host; CLI docs at cli.github.com; user content surface
  // acknowledged in README)
  "cli.github.com",
  "docs.github.com",
  "github.com",
  "raw.githubusercontent.com",
  // GNU
  "gnu.org",
  "www.gnu.org",
  // Google Cloud
  "cloud.google.com",
  // Helm
  "helm.sh",
  // Hugging Face (model cards, tensor metadata, tokenizer configs)
  "huggingface.co",
  // IETF (RFC Editor + Datatracker; protocol citations for security review)
  "datatracker.ietf.org",
  "www.rfc-editor.org",
  // JSON Schema (vocabulary + validation semantics; settings.schema.json)
  "json-schema.org",
  // Kernel
  "kernel.org",
  "www.kernel.org",
  // Kubernetes
  "kubernetes.io",
  // man pages
  "man.freebsd.org",
  "man.openbsd.org",
  "man7.org",
  // Microsoft (Azure, WSL, Hyper-V, Windows prose docs live here; .NET
  // release metadata at dotnet.microsoft.com)
  "docs.microsoft.com",
  "learn.microsoft.com",
  // Mistral AI (model lineup, weights, API docs)
  "docs.mistral.ai",
  // MITRE ATT&CK (TTP framings for threat models)
  "attack.mitre.org",
  // MLX (Apple ML framework docs)
  "ml-explore.github.io",
  // NIST (CSRC for FIPS/SP800 crypto refs; NVD for CVE detail lookups)
  "csrc.nist.gov",
  "nvd.nist.gov",
  // Node.js + npm (TS extension authoring; node:fs/crypto/test APIs)
  "docs.npmjs.com",
  "nodejs.org",
  // Ollama (local-LLM runner docs, model library)
  "ollama.com",
  // Open Container Initiative (image-spec, runtime-spec, distribution-spec)
  "opencontainers.org",
  // OpenGroup (POSIX)
  "pubs.opengroup.org",
  // OWASP (cheat sheets, ASVS, Top 10; security-review-expert)
  "cheatsheetseries.owasp.org",
  "owasp.org",
  // Prettier (formatter config; linter and TS extension tooling)
  "prettier.io",
  // Python (stdlib docs + PEPs)
  "docs.python.org",
  "peps.python.org",
  // pytest (fixture/marker docs)
  "docs.pytest.org",
  // Rust (stdlib + cargo + edition guides; crate API docs; crate metadata)
  "crates.io",
  "doc.rust-lang.org",
  "docs.rs",
  // SemVer (canonical 2.0 spec)
  "semver.org",
  // ShellCheck (per-code SC#### explanation pages; linter and shell-expert)
  "shellcheck.net",
  // Tauri
  "tauri.app",
  "v2.tauri.app",
  // TypeScript (tsconfig, project-references, type-checker rules)
  "www.typescriptlang.org",
  // Ubuntu Discourse (vendor-operated Q&A forum for Ubuntu / Snap / MAAS /
  // Multipass; often the only first-party source for edge cases)
  "discourse.ubuntu.com",
  // vcluster
  "vcluster.com",
]);

function refusal(url: string, reason: string) {
  return {
    content: [
      {
        type: "text" as const,
        text: `web_fetch: refusing '${url}' — ${reason}`,
      },
    ],
    // `details` is required by AgentToolResult<T>; `isError: true` is the
    // duck-typed extra field pi's TUI consumes (see tic-tac-toe.ts example
    // in pi/examples/extensions). T widens to `unknown` for the union with
    // the success-path's typed details object.
    details: undefined,
    isError: true,
  };
}

export function parseUrl(raw: string): URL | { error: string } {
  try {
    return new URL(raw);
  } catch (err) {
    return { error: `not a valid URL (${(err as Error).message})` };
  }
}

type Refusal = ReturnType<typeof refusal>;

/**
 * Resolve one 3xx hop. Returns the refusal to surface, or the next URL to
 * fetch. Each hop's host and scheme are re-validated against the allowlist so
 * an allowlisted host cannot open-redirect the fetch off the allowlist.
 *
 * Extracted from execute() so the redirect policy is unit-testable without a
 * live network or pi.registerTool (#826).
 */
export function resolveRedirect(
  res: Response,
  current: URL,
  rawUrl: string,
  visited: readonly string[],
  hop: number,
): { refusal: Refusal } | { next: URL } {
  const location = res.headers.get("location");
  if (!location) {
    return {
      refusal: refusal(
        current.toString(),
        `HTTP ${res.status} with no Location header`,
      ),
    };
  }
  if (hop === MAX_REDIRECTS) {
    return {
      refusal: refusal(
        rawUrl,
        `redirect limit (${MAX_REDIRECTS}) exceeded; chain: ${visited.join(" → ")} → ${location}`,
      ),
    };
  }
  let next: URL;
  try {
    next = new URL(location, current);
  } catch (err) {
    return {
      refusal: refusal(
        current.toString(),
        `invalid redirect Location '${location}': ${(err as Error).message}`,
      ),
    };
  }
  if (next.protocol !== "https:") {
    return {
      refusal: refusal(
        rawUrl,
        `redirect to non-https URL '${next.toString()}' refused`,
      ),
    };
  }
  if (!ALLOWED_HOSTS.has(next.host)) {
    return {
      refusal: refusal(
        rawUrl,
        `redirect to non-allowlisted host '${next.host}' refused ` +
          `(chain: ${visited.join(" → ")} → ${next.toString()})`,
      ),
    };
  }
  return { next };
}

/**
 * Read a terminal 2xx body under the byte ceilings. Refuses early if the
 * server advertises a Content-Length over HARD_BYTE_CEILING, and aborts the
 * stream if the accumulated bytes cross that ceiling even when the server
 * omits or lies about Content-Length. The body is buffered once and sliced at
 * MAX_BODY_BYTES on truncation.
 *
 * Note: the truncation slice cuts at a byte boundary; `Buffer.toString('utf-8')`
 * then substitutes U+FFFD for any incomplete trailing multi-byte sequence
 * (it does not drop it). Output always stays within MAX_BODY_BYTES.
 *
 * Extracted from execute() so the ceiling/truncation math is unit-testable
 * without a live network or pi.registerTool (#826).
 */
export async function readBodyBounded(
  res: Response,
  current: URL,
): Promise<{ refusal: Refusal } | { body: string; fullBytes: number; truncated: boolean }> {
  const contentLengthHeader = res.headers.get("content-length");
  if (contentLengthHeader !== null) {
    const advertised = Number.parseInt(contentLengthHeader, 10);
    if (Number.isFinite(advertised) && advertised > HARD_BYTE_CEILING) {
      return {
        refusal: refusal(
          current.toString(),
          `response Content-Length ${advertised} exceeds hard ceiling ${HARD_BYTE_CEILING} bytes`,
        ),
      };
    }
  }

  let buf: Buffer;
  try {
    const reader = res.body?.getReader();
    if (!reader) {
      // No streaming body (e.g. empty response) — fall back to text().
      buf = Buffer.from(await res.text(), "utf-8");
    } else {
      const chunks: Buffer[] = [];
      let received = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > HARD_BYTE_CEILING) {
          try {
            await reader.cancel();
          } catch {
            /* ignore cancel errors */
          }
          return {
            refusal: refusal(
              current.toString(),
              `response body exceeded hard ceiling ${HARD_BYTE_CEILING} bytes mid-stream`,
            ),
          };
        }
        chunks.push(Buffer.from(value));
      }
      buf = Buffer.concat(chunks);
    }
  } catch (err) {
    return {
      refusal: refusal(
        current.toString(),
        `response body read failed: ${(err as Error).message}`,
      ),
    };
  }

  const fullBytes = buf.byteLength;
  if (fullBytes > MAX_BODY_BYTES) {
    return {
      body: buf.subarray(0, MAX_BODY_BYTES).toString("utf-8"),
      fullBytes,
      truncated: true,
    };
  }
  return { body: buf.toString("utf-8"), fullBytes, truncated: false };
}

export default function (pi: ExtensionAPI) {
  pi.registerTool({
    name: "web_fetch",
    label: "Web Fetch",
    description:
      "HTTPS GET against an operator-curated first-party documentation " +
      "allowlist; returns the response body (≤256 KB). Refuses non-https " +
      "URLs, non-allowlisted hosts, and redirects that leave the allowlist.",
    promptSnippet:
      "Fetch first-party documentation via web_fetch against the curated allowlist.",
    promptGuidelines: [
      "Use web_fetch to corroborate findings against first-party documentation when the URL is known. Cite the fetched URL in any resulting finding.",
      "web_fetch only accepts https:// URLs against an allowlist of first-party documentation hosts (see agent/extensions/web-fetch/README.md). Non-allowlisted hosts are refused.",
    ],
    parameters: Type.Object({
      url: Type.String({
        description:
          "Absolute https:// URL on the first-party-docs allowlist. " +
          "See agent/extensions/web-fetch/README.md for the host list.",
      }),
      accept: Type.Optional(
        Type.String({
          description:
            "Optional Accept header value. Defaults to text/html and plain text.",
        }),
      ),
    }),
    async execute(_toolCallId, params, signal) {
      const { url: rawUrl, accept } = params;

      const parsed = parseUrl(rawUrl);
      if ("error" in parsed) {
        return refusal(rawUrl, parsed.error);
      }
      if (parsed.protocol !== "https:") {
        return refusal(
          rawUrl,
          `URL scheme must be https: (got '${parsed.protocol}'). web_fetch refuses non-https URLs.`,
        );
      }
      if (!ALLOWED_HOSTS.has(parsed.host)) {
        return refusal(
          rawUrl,
          `host '${parsed.host}' is not on the first-party-docs allowlist. ` +
            `Adding a host requires a PR — see agent/extensions/web-fetch/README.md § Adding a host.`,
        );
      }

      // Manual redirect loop so each hop's host is re-validated against the
      // allowlist. Defeats open-redirect bypass (e.g. an allowlisted host's
      // /url?q= redirector pointing to an arbitrary destination). The per-hop
      // policy and the body-ceiling/truncation math live in resolveRedirect()
      // and readBodyBounded() so both are unit-testable without a network.
      let current: URL = parsed;
      const visited: string[] = [current.toString()];
      for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
        let res: Response;
        try {
          res = await fetch(current, {
            method: "GET",
            redirect: "manual",
            signal,
            headers: {
              "user-agent": USER_AGENT,
              accept: accept ?? DEFAULT_ACCEPT,
            },
          });
        } catch (err) {
          return refusal(
            current.toString(),
            `network error: ${(err as Error).message}`,
          );
        }

        // Redirect: re-validate next host against allowlist before following.
        if (res.status >= 300 && res.status < 400) {
          const outcome = resolveRedirect(res, current, rawUrl, visited, hop);
          if ("refusal" in outcome) {
            return outcome.refusal;
          }
          current = outcome.next;
          visited.push(current.toString());
          continue;
        }

        if (!res.ok) {
          return refusal(
            current.toString(),
            `HTTP ${res.status} ${res.statusText}`,
          );
        }

        const outcome = await readBodyBounded(res, current);
        if ("refusal" in outcome) {
          return outcome.refusal;
        }
        const { body, fullBytes, truncated } = outcome;

        const chainNote =
          visited.length > 1
            ? `\nRedirect chain: ${visited.join(" → ")}`
            : "";
        const truncNote = truncated
          ? `\n[truncated to ${MAX_BODY_BYTES} bytes of ${fullBytes}]`
          : "";

        return {
          content: [
            {
              type: "text" as const,
              text: `${res.status} ${current.toString()}${chainNote}${truncNote}\n\n${body}`,
            },
          ],
          details: {
            url: current.toString(),
            status: res.status,
            bytes: Math.min(fullBytes, MAX_BODY_BYTES),
            originalBytes: fullBytes,
            truncated,
            redirectChain: visited,
          },
        };
      }

      // Unreachable: the loop body either returns or continues; MAX_REDIRECTS
      // exhaustion returns inside resolveRedirect's hop-limit branch.
      return refusal(rawUrl, "internal: redirect loop exited unexpectedly");
    },
  });
}
