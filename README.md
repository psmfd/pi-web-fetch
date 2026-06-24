# web-fetch — pi extension

> **First-party** to this repo. Registers the `web_fetch` tool used by research-specialist subagents to corroborate findings against authoritative first-party documentation.

## Purpose

Several subagents — `security-review-expert`, `code-review-expert`, `shell-expert`, the cloud and infra specialists, language specialists, container/orchestration specialists, and `docs-expert` — claim in their descriptions that they cite first-party documentation. Prior to this extension they could not: pi 0.75.4 ships only `read`, `bash`, `edit`, `write` built-ins, and the bare `web` tool listed in those wrappers' `tools:` frontmatter was a silent no-op (root cause tracked in [#152](https://github.com/TheSemicolon/pi_config/issues/152)). The result was opus-pinned reviewers citing from cached model knowledge and flagging claims as "not corroborated" when challenged.

`web_fetch(url, accept?)` performs an HTTPS GET against an operator-curated allowlist of first-party documentation hosts and returns the response body (≤256 KB). It is read-only, requires no credentials, and is the only network-capable tool in `agent/extensions/`.

Tracking issue: [#151](https://github.com/TheSemicolon/pi_config/issues/151). Substrate decision: [ADR-0015](../../../adrs/0015-network-capable-extensions-and-the-first-party-docs-allowlist.md).

## Security boundary

The single security boundary is the **host allowlist** in `index.ts` (the `ALLOWED_HOSTS` set). The threat model assumes:

- The agent's reasoning can be steered by adversarial content in any file or tool output it reads (prompt injection).
- An attacker who can steer reasoning will try to drive the agent to fetch arbitrary URLs (SSRF, data exfiltration to attacker-controlled hosts, credential probing of internal endpoints).
- The defense is operator-curated host selection at allowlist-edit time: an attacker cannot add a host without a reviewed PR.

This is a defense-in-depth posture, not perimeter security. Subordinate enforcement:

| Rule | Enforcement |
|---|---|
| URL scheme must be `https:` | Hard refusal — refuses `http:`, `file:`, `data:`, anything else |
| URL host must be in `ALLOWED_HOSTS` | Hard refusal |
| 3xx redirects must each land on an allowlisted host | Hard refusal at the offending hop; max 3 hops total. Defeats open-redirector bypass on otherwise-allowlisted hosts. |
| Response body >256 KB | Truncated to 256 KB (not refused); truncation is reported in the tool result `details` |
| Non-2xx terminal response | Returned as tool error with status code |

No `SKIP_*` env override exists. Adding a host requires a PR.

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

## Allowlist

The full list lives in `index.ts` `ALLOWED_HOSTS`. Coverage matrix at the time of authoring:

| Domain | Hosts | Covers |
|---|---|---|
| ADR | `adr.github.io` | MADR template — canonical reference for our `adr-required` rule |
| Ansible | `docs.ansible.com` | `ansible-expert` |
| Anthropic | `docs.anthropic.com`, `docs.claude.com` | Claude Code installer + model docs; mid-migration between the two hosts, both kept live during the transition |
| Apple | `developer.apple.com` | macOS, Swift, Xcode |
| Astral | `docs.astral.sh` | Ruff (linter) + uv (package manager) |
| AWS | `docs.aws.amazon.com` | `aws-expert` |
| AWS re:Post | `repost.aws` | Vendor-operated Q&A forum (replaces AWS Developer Forums) |
| Canonical | `canonical.com` | Ubuntu / Multipass / LXD / MAAS / snap / juju marketing + install surface (deep docs live at `documentation.ubuntu.com`) — sandbox-substrate evaluation |
| Checkmarx | `docs.checkmarx.com` | `checkmarx-expert` |
| Conventional Commits | `www.conventionalcommits.org` | Spec referenced by the `conventional-commits` rule |
| CVE | `www.cve.org` | MITRE-operated CVE catalog — `security-review-expert` |
| Docker | `docs.docker.com` | `docker-expert` |
| Documentation.Ubuntu.com | `documentation.ubuntu.com` | Canonical's tightly-scoped first-party docs surface (`multipass.run/docs` and `canonical.com/<product>/docs` redirect here) — sandbox-substrate evaluation |
| .NET | `dotnet.microsoft.com` | Release/SDK/lifecycle metadata (prose docs at `learn.microsoft.com`) — `dotnet-expert` |
| ESLint | `eslint.org` | Rule reference + flat-config docs — `linter`, TS extension tooling |
| Firecracker | `firecracker-microvm.github.io` | AWS microVM — sandbox-substrate evaluation |
| freedesktop | `freedesktop.org`, `specifications.freedesktop.org`, `www.freedesktop.org` | XDG, systemd-adjacent, Wayland |
| Git | `git-scm.com` | Canonical `git` / `git-config` docs — `gitflow-expert` |
| GitHub | `cli.github.com`, `docs.github.com`, `github.com`, `raw.githubusercontent.com` | upstream pi, ADRs in the wild, source citation, REST API / Actions / branch-protection / GHCR / fine-grained PAT docs (`docs.github.com`), `gh` CLI reference (`cli.github.com`). **High user-content surface — see note below.** |
| GNU | `gnu.org`, `www.gnu.org` | Bash, coreutils, glibc |
| Google Cloud | `cloud.google.com` | (no GCP specialist yet, but referenced in cross-cloud discussions) |
| Helm | `helm.sh` | `helm-expert` |
| Hugging Face | `huggingface.co` | Model cards, tensor/tokenizer metadata for local-inference planning. **High user-content surface — see note below.** |
| IETF | `datatracker.ietf.org`, `www.rfc-editor.org` | RFC + draft citations for protocol-level review (HTTP, OAuth, TLS, JWT, etc.) |
| JSON Schema | `json-schema.org` | Vocabulary + validation semantics for `settings.schema.json` and adjacent schemas |
| Kata Containers | `katacontainers.io` | CNCF per-container microVM OCI runtime — sandbox-substrate evaluation |
| Kernel | `kernel.org`, `www.kernel.org` | Linux kernel docs |
| Kubernetes | `kubernetes.io` | `helm-expert`, `vcluster-expert` |
| man pages | `man.freebsd.org`, `man.openbsd.org`, `man7.org` | `shell-expert`, POSIX, system calls |
| Microsoft | `docs.microsoft.com`, `learn.microsoft.com` | `azure-infra-expert`, `azure-devops-expert`, `dotnet-expert`, `wsl2-expert`, `hyperv-expert` |
| Mistral AI | `docs.mistral.ai` | Mistral model lineup, weights, inference/serving guidance |
| MITRE ATT&CK | `attack.mitre.org` | TTP framings for threat models — `security-review-expert` |
| MLX | `ml-explore.github.io` | Apple MLX framework / MLX-LM (Apple Silicon local inference) |
| Modal | `modal.com` | Serverless container/GPU runtime — hosted sandbox-substrate evaluation |
| Multipass | `multipass.run` | Canonical cross-platform Ubuntu VMs (Hypervisor.framework / KVM / Hyper-V) — sandbox-substrate evaluation |
| NIST | `csrc.nist.gov`, `nvd.nist.gov` | FIPS / SP800 crypto refs (`csrc`); CVE detail lookups (`nvd`) — `security-review-expert` |
| Node.js + npm | `docs.npmjs.com`, `nodejs.org` | TS extension authoring; `node:fs` / `node:crypto` / `node:test` APIs; package.json semantics |
| Ollama | `ollama.com` | Local-LLM runner docs and model library. **High user-content surface — see note below.** |
| OCI | `opencontainers.org` | Open Container Initiative (image-spec, runtime-spec, distribution-spec) — packaging/distribution research |
| OpenGroup | `pubs.opengroup.org` | POSIX (`shell-expert`) |
| OWASP | `cheatsheetseries.owasp.org`, `owasp.org` | Cheat sheets, ASVS, Top 10 — `security-review-expert` |
| Podman | `docs.podman.io` | Podman + Podman-machine (macOS backend uses krunkit/libkrun) — sandbox-substrate evaluation |
| Prettier | `prettier.io` | Formatter config — `linter`, TS extension tooling |
| Python | `docs.python.org`, `peps.python.org` | Stdlib docs + PEP citations (typing, packaging, async) |
| pytest | `docs.pytest.org` | Fixture/marker docs for Python testing |
| QEMU | `qemu.org`, `wiki.qemu.org`, `www.qemu.org` | Cross-platform reference hypervisor (HVF/KVM/WHPX accelerators) — sandbox-substrate evaluation |
| Rust | `crates.io`, `doc.rust-lang.org`, `docs.rs` | Stdlib + cargo + edition guides (`doc.rust-lang.org`), crate API docs (`docs.rs`), crate metadata (`crates.io`) — `tauri-expert` |
| SemVer | `semver.org` | Canonical 2.0 spec |
| ShellCheck | `shellcheck.net` | Per-code SC#### explanation pages — `linter`, `shell-expert` |
| Tauri | `tauri.app`, `v2.tauri.app` | `tauri-expert` |
| TypeScript | `www.typescriptlang.org` | tsconfig, project-references, type-checker rules — TS extension authoring |
| Ubuntu Discourse | `discourse.ubuntu.com` | Vendor-operated Q&A forum (Ubuntu / Snap / MAAS / Multipass); often the only first-party source for edge cases |
| vcluster | `vcluster.com` | `vcluster-expert` |
| Wasmer | `wasmer.io`, `docs.wasmer.io` | WASM runtime (cross-platform WASI sandbox) — sandbox-substrate evaluation |
| WasmEdge | `wasmedge.org` | CNCF WASM runtime (cross-platform WASI sandbox) — sandbox-substrate evaluation |

### Note on `github.com`

`github.com` is a load-bearing host (upstream pi source, ADR references, real-world repo links) but also a high user-content surface — any repo can host arbitrary markdown, and `raw.githubusercontent.com` returns raw file contents from any public repo. We accept this trade-off for v1 because:

1. The agent is already reading user-content-shaped material (the working copy, issue bodies). `github.com` doesn't materially expand the attack surface beyond what `read` already exposes.
2. Restricting to specific repos (`github.com/earendil-works/pi`, `github.com/TheSemicolon/pi_config`) would require path-prefix matching, which `URL.host` doesn't support; we'd need to compare `URL.pathname` separately. Tractable but adds complexity. Revisit if abuse surfaces.

If a future incident motivates tightening, the path-prefix approach is the upgrade path.

### Note on `huggingface.co` and `ollama.com`

Both hosts follow the same shape as `github.com`: curated first-party documentation surfaces (`/docs/...`, `/library/<name>`) coexist with arbitrary user-published content (model repos at `/<user>/<model>`, Community/Discussions tabs, user-authored model-card markdown). We accept the same v1 trade-off for the same reasons enumerated in the `github.com` note above:

1. The agent already reads user-influenceable content via `read` and tool outputs; allowlisting these hosts at apex does not materially expand the prompt-injection-driven SSRF surface that `URL.host` allowlisting is designed to bound.
2. Restricting to specific path prefixes (e.g. `huggingface.co/docs/`, `huggingface.co/mistralai/`, `ollama.com/library/`) would require `URL.pathname` matching alongside the existing `URL.host` check. Tractable but unimplemented; revisit if abuse surfaces.

The redirect re-validation loop (every hop's host is re-checked against `ALLOWED_HOSTS`, non-https Locations are refused) continues to defeat open-redirector escape attempts from these hosts — e.g. `huggingface.co` LFS download links that 302 to a distinct `cdn-lfs.huggingface.co` host are hard-refused at the redirect hop.

### Adding a host

1. Open a PR adding the host (alphabetized) to `ALLOWED_HOSTS` in `index.ts`.
2. Update the coverage matrix table above.
3. PR description must state which subagent(s) need the host and what first-party-doc URL motivates the addition.
4. Reviewer asks: is this a first-party documentation host? Does the host serve user-generated content as a primary surface? If user content is incidental (e.g. blog comments on an official doc page), the host is acceptable; if it's primary (a forum, Stack Overflow, Medium), it is not.

## Interaction with other extensions

- **`secrets-guard/`**: `web_fetch` is read-only and writes nothing to disk. No secrets-guard coverage is needed — the tool cannot exfiltrate via committed files. Content surfaced to the model is bounded by the host allowlist.
- **`bash-destructive-guard/`**: no interaction — `web_fetch` does not invoke shell.
- **`subagent/`**: subagents that need `web_fetch` must list it in their `tools:` frontmatter. Per [#152](https://github.com/TheSemicolon/pi_config/issues/152), unknown tool names in that frontmatter are currently dropped silently; a future patch will warn or fail.
- **`artifact-handoff/`**: no interaction — separate concerns.

## What this extension explicitly does NOT do

- **No search.** There is no `web_search` tool. Agents must know the URL or follow links inside fetched documents. This is a deliberate scope boundary; the design implications of adding search (allowlist erosion via attacker-influenced URL discovery, query exfiltration to a third-party search provider, citation-replay break) are documented in [ADR-0015](../../../adrs/0015-network-capable-extensions-and-the-first-party-docs-allowlist.md) § Rejected.
- **No browser automation.** Static `fetch` only — no JavaScript execution, no DOM, no cookies, no session state.
- **No authenticated fetches.** No credentials are read, stored, or sent. Documentation lookup is out of any reasonable auth threat model.
- **No `http:`, `file:`, or `data:` URLs.** HTTPS only.

## Smoke test

Manual smoke (per #151 acceptance criteria):

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

## References

- Tracking issue: [#151](https://github.com/TheSemicolon/pi_config/issues/151)
- ADR: [ADR-0015](../../../adrs/0015-network-capable-extensions-and-the-first-party-docs-allowlist.md)
- Related follow-ups: [#152](https://github.com/TheSemicolon/pi_config/issues/152) (subagent unknown-tool diagnosability), [#153](https://github.com/TheSemicolon/pi_config/issues/153) (research-subagent issue-body access)
- Extension API: `~/.cache/pi_config/pi-v0.75.5/pi/docs/extensions.md`
