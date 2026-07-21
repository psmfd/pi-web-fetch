/**
 * web-fetch — integration tests for the registered web_fetch tool (#826).
 *
 * Loads the default factory through a fake `pi` that captures registerTool,
 * then drives `execute` with a mocked global `fetch` so the whole path —
 * scheme/host gate → manual redirect loop → body bounding → result shape — is
 * exercised end-to-end. No live network.
 */

import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import webFetch from "../index.ts";

interface ToolResult {
  isError?: boolean;
  content: { readonly text: string }[];
  details?:
    | {
        url: string;
        status: number;
        bytes: number;
        originalBytes: number;
        truncated: boolean;
        redirectChain: string[];
      }
    | undefined;
}
interface Tool {
  name: string;
  execute: (
    id: string,
    params: { url: string; accept?: string },
    signal: unknown,
  ) => Promise<ToolResult>;
}

function loadTool(): Tool {
  let captured: Tool | undefined;
  const pi = {
    registerTool(t: Tool) {
      captured = t;
    },
  };
  webFetch(pi as never);
  if (!captured) throw new Error("web_fetch tool was not registered");
  return captured;
}

const tool = loadTool();
const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

// Install a fetch mock that routes on the requested URL string.
function mockFetch(router: (url: string) => Response | Promise<Response>): void {
  globalThis.fetch = (async (input: unknown): Promise<Response> => {
    const url =
      input instanceof URL
        ? input.toString()
        : typeof input === "string"
          ? input
          : String((input as { url?: string }).url ?? input);
    return router(url);
  }) as typeof globalThis.fetch;
}

test("registers a tool named web_fetch", () => {
  assert.equal(tool.name, "web_fetch");
});

test("refuses a non-https URL before any fetch", async () => {
  let called = false;
  mockFetch(() => {
    called = true;
    return new Response("x");
  });
  const out = await tool.execute("1", { url: "http://man7.org/" }, undefined);
  assert.equal(out.isError, true);
  assert.match(out.content[0].text, /scheme must be https/);
  assert.equal(called, false, "fetch must not run for a refused scheme");
});

test("refuses a non-allowlisted host before any fetch", async () => {
  let called = false;
  mockFetch(() => {
    called = true;
    return new Response("x");
  });
  const out = await tool.execute("2", { url: "https://example.com/" }, undefined);
  assert.equal(out.isError, true);
  assert.match(out.content[0].text, /not on the first-party-docs allowlist/);
  assert.equal(called, false);
});

test("refuses an unparseable URL", async () => {
  const out = await tool.execute("3", { url: "://nope" }, undefined);
  assert.equal(out.isError, true);
  assert.match(out.content[0].text, /not a valid URL/);
});

test("returns a 200 body with populated details on the success path", async () => {
  mockFetch(() => new Response("MANUAL CONTENT", { status: 200 }));
  const out = await tool.execute(
    "4",
    { url: "https://www.gnu.org/software/bash/manual/bash.html" },
    undefined,
  );
  assert.notEqual(out.isError, true);
  assert.match(out.content[0].text, /^200 https:\/\/www\.gnu\.org/);
  assert.match(out.content[0].text, /MANUAL CONTENT/);
  assert.equal(out.details?.status, 200);
  assert.equal(out.details?.truncated, false);
  assert.deepEqual(out.details?.redirectChain, [
    "https://www.gnu.org/software/bash/manual/bash.html",
  ]);
});

test("follows a redirect to an allowlisted host and reports the chain", async () => {
  mockFetch((url) => {
    if (url === "https://docs.microsoft.com/dotnet") {
      return new Response(null, {
        status: 302,
        headers: { location: "https://learn.microsoft.com/dotnet" },
      });
    }
    return new Response("FINAL", { status: 200 });
  });
  const out = await tool.execute(
    "5",
    { url: "https://docs.microsoft.com/dotnet" },
    undefined,
  );
  assert.notEqual(out.isError, true);
  assert.match(out.content[0].text, /FINAL/);
  assert.match(out.content[0].text, /Redirect chain:/);
  assert.deepEqual(out.details?.redirectChain, [
    "https://docs.microsoft.com/dotnet",
    "https://learn.microsoft.com/dotnet",
  ]);
});

test("refuses end-to-end when a redirect leaves the allowlist", async () => {
  mockFetch((url) => {
    if (url === "https://github.com/redir") {
      return new Response(null, {
        status: 302,
        headers: { location: "https://evil.example.com/" },
      });
    }
    return new Response("should not reach", { status: 200 });
  });
  const out = await tool.execute(
    "6",
    { url: "https://github.com/redir" },
    undefined,
  );
  assert.equal(out.isError, true);
  assert.match(out.content[0].text, /non-allowlisted host 'evil\.example\.com'/);
});

test("surfaces a non-2xx terminal response as a refusal", async () => {
  mockFetch(() => new Response("nope", { status: 404, statusText: "Not Found" }));
  const out = await tool.execute("7", { url: "https://man7.org/missing" }, undefined);
  assert.equal(out.isError, true);
  assert.match(out.content[0].text, /HTTP 404/);
});

test("surfaces a network error as a refusal", async () => {
  mockFetch(() => {
    throw new Error("ECONNREFUSED");
  });
  const out = await tool.execute("8", { url: "https://man7.org/x" }, undefined);
  assert.equal(out.isError, true);
  assert.match(out.content[0].text, /network error: ECONNREFUSED/);
});

test("truncates an oversized body and reports it in details", async () => {
  const big = "b".repeat(262144 + 4096); // > MAX_BODY_BYTES, ASCII
  mockFetch(() => new Response(big, { status: 200 }));
  const out = await tool.execute("9", { url: "https://man7.org/big" }, undefined);
  assert.notEqual(out.isError, true);
  assert.equal(out.details?.truncated, true);
  assert.equal(out.details?.originalBytes, 262144 + 4096);
  assert.equal(out.details?.bytes, 262144);
  assert.match(out.content[0].text, /\[truncated to 262144 bytes of 266240\]/);
});
