/**
 * web-fetch — unit tests for the extracted security helpers (#826, epic #780 item 17).
 *
 * These exercise the SSRF-boundary logic directly — allowlist membership, the
 * per-hop redirect re-validation policy, and the body ceiling/truncation math —
 * without a live network or pi.registerTool. The companion execute.test.ts
 * covers the same helpers wired together through the registered tool.
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ALLOWED_HOSTS,
  HARD_BYTE_CEILING,
  MAX_BODY_BYTES,
  parseUrl,
  readBodyBounded,
  resolveRedirect,
} from "../index.ts";

// A minimal Response-shaped stub for the redirect helper (only .status and
// .headers.get("location") are read).
function redirectResponse(status: number, location?: string): Response {
  const headers = new Headers();
  if (location !== undefined) headers.set("location", location);
  return { status, headers } as unknown as Response;
}

// A streaming Response with NO content-length header, so readBodyBounded
// exercises its mid-stream reader path rather than the Content-Length
// pre-check. `chunkBytes`/`chunks` control the streamed size.
function streamResponse(
  body: string,
  headers: Record<string, string> = {},
): Response {
  const bytes = Buffer.from(body, "utf-8");
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      // Emit in 64 KB slices so a large body genuinely streams in chunks.
      const step = 65536;
      for (let i = 0; i < bytes.byteLength; i += step) {
        controller.enqueue(new Uint8Array(bytes.subarray(i, i + step)));
      }
      controller.close();
    },
  });
  return new Response(stream, { status: 200, headers });
}

// --- ALLOWED_HOSTS ---------------------------------------------------------

test("allowlist keeps load-bearing first-party hosts", () => {
  for (const host of [
    "docs.aws.amazon.com",
    "learn.microsoft.com",
    "github.com",
    "www.gnu.org",
    "man7.org",
    "opencontainers.org", // re-justified as packaging/distribution research
    "repost.aws", // vendor-operated first-party Q&A forum (kept)
    "discourse.ubuntu.com", // vendor-operated first-party Q&A forum (kept)
  ]) {
    assert.ok(ALLOWED_HOSTS.has(host), `${host} should be allowlisted`);
  }
});

test("the 13 rescinded sandbox-substrate hosts are removed (ADR-0020, #826)", () => {
  // These were added by PRs #202/#203 solely for the substrate-ζ replacement
  // research that ADR-0020 rescinded; no agent/skill consumes them. This lock
  // test fails if any is reintroduced without a consuming subagent.
  for (const host of [
    "canonical.com",
    "documentation.ubuntu.com",
    "firecracker-microvm.github.io",
    "katacontainers.io",
    "modal.com",
    "multipass.run",
    "docs.podman.io",
    "qemu.org",
    "wiki.qemu.org",
    "www.qemu.org",
    "wasmer.io",
    "docs.wasmer.io",
    "wasmedge.org",
  ]) {
    assert.equal(
      ALLOWED_HOSTS.has(host),
      false,
      `${host} should NOT be allowlisted`,
    );
  }
});

// --- parseUrl --------------------------------------------------------------

test("parseUrl returns a URL for a valid absolute URL", () => {
  const out = parseUrl("https://man7.org/linux/man-pages/");
  assert.ok(out instanceof URL);
  assert.equal(out.host, "man7.org");
});

test("parseUrl returns an error object for a non-URL string", () => {
  const out = parseUrl("not a url");
  assert.ok("error" in out);
});

// --- resolveRedirect -------------------------------------------------------

test("resolveRedirect follows a redirect to an allowlisted https host", () => {
  const res = redirectResponse(302, "https://learn.microsoft.com/dotnet");
  const out = resolveRedirect(
    res,
    new URL("https://docs.microsoft.com/x"),
    "https://docs.microsoft.com/x",
    ["https://docs.microsoft.com/x"],
    0,
  );
  assert.ok("next" in out);
  assert.equal((out as { next: URL }).next.host, "learn.microsoft.com");
});

test("resolveRedirect resolves a relative Location against the current URL", () => {
  const res = redirectResponse(301, "/software/bash/manual/bash.html");
  const out = resolveRedirect(
    res,
    new URL("https://www.gnu.org/index.html"),
    "https://www.gnu.org/index.html",
    ["https://www.gnu.org/index.html"],
    0,
  );
  assert.ok("next" in out);
  assert.equal(
    (out as { next: URL }).next.toString(),
    "https://www.gnu.org/software/bash/manual/bash.html",
  );
});

test("resolveRedirect refuses a redirect to a non-allowlisted host", () => {
  const res = redirectResponse(302, "https://evil.example.com/");
  const out = resolveRedirect(
    res,
    new URL("https://github.com/x"),
    "https://github.com/x",
    ["https://github.com/x"],
    0,
  );
  assert.ok("refusal" in out);
  assert.match(
    (out as { refusal: { content: { text: string }[] } }).refusal.content[0]
      .text,
    /non-allowlisted host 'evil\.example\.com'/,
  );
});

test("resolveRedirect refuses a redirect to a non-https URL", () => {
  const res = redirectResponse(302, "http://man7.org/");
  const out = resolveRedirect(
    res,
    new URL("https://man7.org/x"),
    "https://man7.org/x",
    ["https://man7.org/x"],
    0,
  );
  assert.ok("refusal" in out);
  assert.match(
    (out as { refusal: { content: { text: string }[] } }).refusal.content[0]
      .text,
    /non-https URL/,
  );
});

test("resolveRedirect refuses a redirect to an allowlisted host on a non-443 port", () => {
  // URL.host (not hostname) is compared, so :8443 does not match the canonical
  // port-less entry — documented behavior in index.ts.
  const res = redirectResponse(302, "https://github.com:8443/x");
  const out = resolveRedirect(
    res,
    new URL("https://github.com/x"),
    "https://github.com/x",
    ["https://github.com/x"],
    0,
  );
  assert.ok("refusal" in out);
  assert.match(
    (out as { refusal: { content: { text: string }[] } }).refusal.content[0]
      .text,
    /non-allowlisted host 'github\.com:8443'/,
  );
});

test("resolveRedirect refuses a 3xx with no Location header", () => {
  const res = redirectResponse(302);
  const out = resolveRedirect(
    res,
    new URL("https://github.com/x"),
    "https://github.com/x",
    ["https://github.com/x"],
    0,
  );
  assert.ok("refusal" in out);
  assert.match(
    (out as { refusal: { content: { text: string }[] } }).refusal.content[0]
      .text,
    /no Location header/,
  );
});

test("resolveRedirect refuses once the hop count reaches MAX_REDIRECTS", () => {
  const res = redirectResponse(302, "https://github.com/next");
  const out = resolveRedirect(
    res,
    new URL("https://github.com/x"),
    "https://github.com/x",
    ["https://github.com/x"],
    3, // MAX_REDIRECTS
  );
  assert.ok("refusal" in out);
  assert.match(
    (out as { refusal: { content: { text: string }[] } }).refusal.content[0]
      .text,
    /redirect limit \(3\) exceeded/,
  );
});

// --- readBodyBounded -------------------------------------------------------

test("readBodyBounded returns a small body verbatim, not truncated", async () => {
  const out = await readBodyBounded(
    streamResponse("hello world"),
    new URL("https://man7.org/x"),
  );
  assert.ok("body" in out);
  const ok = out as { body: string; fullBytes: number; truncated: boolean };
  assert.equal(ok.body, "hello world");
  assert.equal(ok.truncated, false);
  assert.equal(ok.fullBytes, 11);
});

test("readBodyBounded truncates a body over MAX_BODY_BYTES at the byte cap", async () => {
  const big = "a".repeat(MAX_BODY_BYTES + 5000); // ASCII: 1 byte/char
  const out = await readBodyBounded(
    streamResponse(big),
    new URL("https://man7.org/x"),
  );
  assert.ok("body" in out);
  const ok = out as { body: string; fullBytes: number; truncated: boolean };
  assert.equal(ok.truncated, true);
  assert.equal(ok.fullBytes, MAX_BODY_BYTES + 5000);
  assert.equal(Buffer.byteLength(ok.body, "utf-8"), MAX_BODY_BYTES);
});

test("readBodyBounded refuses when Content-Length exceeds the hard ceiling", async () => {
  const res = new Response("small", {
    status: 200,
    headers: { "content-length": String(HARD_BYTE_CEILING + 1) },
  });
  const out = await readBodyBounded(res, new URL("https://man7.org/x"));
  assert.ok("refusal" in out);
  assert.match(
    (out as { refusal: { content: { text: string }[] } }).refusal.content[0]
      .text,
    /exceeds hard ceiling/,
  );
});

test("readBodyBounded aborts mid-stream when bytes cross the hard ceiling without Content-Length", async () => {
  const huge = "a".repeat(HARD_BYTE_CEILING + 100000);
  const out = await readBodyBounded(
    streamResponse(huge), // stream body → no content-length header
    new URL("https://man7.org/x"),
  );
  assert.ok("refusal" in out);
  assert.match(
    (out as { refusal: { content: { text: string }[] } }).refusal.content[0]
      .text,
    /exceeded hard ceiling .* mid-stream/,
  );
});
