import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeFunctionReference } from "convex/server";
import { convexBetterAuthNextJs } from "./index.js";

const { headersMock, fetchQueryMock } = vi.hoisted(() => ({
  headersMock: vi.fn(),
  fetchQueryMock: vi.fn(),
}));

vi.mock("next/headers.js", () => ({ headers: headersMock }));

vi.mock("convex/nextjs", () => ({
  fetchQuery: fetchQueryMock,
  fetchMutation: vi.fn(),
  fetchAction: vi.fn(),
  preloadQuery: vi.fn(),
}));

const SITE_URL = "https://test.convex.site";
const CONVEX_URL = "https://test.convex.cloud";

const setup = () => {
  const { handler } = convexBetterAuthNextJs({
    convexUrl: CONVEX_URL,
    convexSiteUrl: SITE_URL,
  });
  const fetchSpy = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValue(new Response());
  return { handler, fetchSpy };
};

const initOf = (spy: ReturnType<typeof vi.spyOn>): RequestInit =>
  (spy.mock.calls[0]?.[1] as RequestInit) ?? {};

const headersOf = (spy: ReturnType<typeof vi.spyOn>): Headers =>
  new Headers(initOf(spy).headers);

describe("convexBetterAuthNextJs handler", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("strips hop-by-hop headers from the forwarded request", async () => {
    const { handler, fetchSpy } = setup();
    const request = new Request(
      "https://app.example.com/api/auth/sign-in/email",
      {
        method: "POST",
        headers: {
          "transfer-encoding": "chunked",
          "content-length": "42",
          connection: "keep-alive",
          "content-type": "application/json",
        },
        body: JSON.stringify({ email: "test@example.com" }),
      }
    );
    await handler.POST(request);
    const headers = headersOf(fetchSpy);
    expect(headers.get("transfer-encoding")).toBeNull();
    expect(headers.get("content-length")).toBeNull();
    expect(headers.get("connection")).toBeNull();
  });

  it("forwards to upstream URL preserving path and query", async () => {
    const { handler, fetchSpy } = setup();
    const request = new Request(
      "https://app.example.com/api/auth/sign-in/email?foo=bar",
      { method: "POST", body: "{}" }
    );
    await handler.POST(request);
    expect(fetchSpy.mock.calls[0]?.[0]).toBe(
      `${SITE_URL}/api/auth/sign-in/email?foo=bar`
    );
  });

  it("sets host and forwarding headers", async () => {
    const { handler, fetchSpy } = setup();
    const request = new Request(
      "https://app.example.com/api/auth/sign-in/email",
      { method: "POST", body: "{}" }
    );
    await handler.POST(request);
    const headers = headersOf(fetchSpy);
    expect(headers.get("host")).toBe(new URL(SITE_URL).host);
    expect(headers.get("x-forwarded-host")).toBe("app.example.com");
    expect(headers.get("x-forwarded-proto")).toBe("https");
    expect(headers.get("x-better-auth-forwarded-host")).toBe("app.example.com");
    expect(headers.get("x-better-auth-forwarded-proto")).toBe("https");
  });

  it("buffers POST body and forwards as ArrayBuffer", async () => {
    const { handler, fetchSpy } = setup();
    const body = JSON.stringify({ email: "test@example.com" });
    const request = new Request(
      "https://app.example.com/api/auth/sign-in/email",
      { method: "POST", body }
    );
    await handler.POST(request);
    const init = initOf(fetchSpy);
    expect(init.body).toBeInstanceOf(ArrayBuffer);
    expect(new TextDecoder().decode(init.body as ArrayBuffer)).toBe(body);
  });

  it("does not set body for GET requests", async () => {
    const { handler, fetchSpy } = setup();
    const request = new Request(
      "https://app.example.com/api/auth/get-session",
      { method: "GET" }
    );
    await handler.GET(request);
    expect(initOf(fetchSpy).body).toBeUndefined();
  });

  it("does not set body for empty POST", async () => {
    const { handler, fetchSpy } = setup();
    const request = new Request("https://app.example.com/api/auth/sign-out", {
      method: "POST",
    });
    await handler.POST(request);
    expect(initOf(fetchSpy).body).toBeUndefined();
  });
});

const FRESH_JWT = "fresh.jwt.token";

// jose.decodeJwt only base64url decodes the payload, so an unsigned token is
// enough to exercise the expiration check in getToken.
const makeJwt = (expiresInSeconds: number) =>
  [
    JSON.stringify({ alg: "RS256", typ: "JWT" }),
    JSON.stringify({ exp: Math.floor(Date.now() / 1000) + expiresInSeconds }),
    "signature",
  ]
    .map((segment) =>
      btoa(segment).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
    )
    .join(".");

const isAuthError = (error: unknown) =>
  error instanceof Error && /auth/i.test(error.message);

const query = makeFunctionReference<"query">("todos:get");

describe("convexBetterAuthNextJs jwt cache retry", () => {
  const setupJwtCache = ({ cookieJwt }: { cookieJwt?: string } = {}) => {
    headersMock.mockReturnValue(
      new Headers(
        cookieJwt ? { cookie: `better-auth.convex_jwt=${cookieJwt}` } : {}
      )
    );
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ token: FRESH_JWT }), {
        headers: { "content-type": "application/json" },
      })
    );
    return convexBetterAuthNextJs({
      convexUrl: CONVEX_URL,
      convexSiteUrl: SITE_URL,
      jwtCache: { enabled: true, isAuthError },
    });
  };

  beforeEach(() => {
    headersMock.mockReset();
    fetchQueryMock.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("refetches the jwt and retries once when a cached jwt is rejected", async () => {
    const cachedJwt = makeJwt(300);
    const { fetchAuthQuery } = setupJwtCache({ cookieJwt: cachedJwt });
    fetchQueryMock
      .mockRejectedValueOnce(new Error("Unauthenticated"))
      .mockResolvedValueOnce("todos");

    await expect(fetchAuthQuery(query)).resolves.toBe("todos");
    expect(fetchQueryMock).toHaveBeenCalledTimes(2);
    expect(fetchQueryMock.mock.calls[0]?.[2]).toEqual({ token: cachedJwt });
    expect(fetchQueryMock.mock.calls[1]?.[2]).toEqual({ token: FRESH_JWT });
  });

  it("does not retry when the error is not auth related", async () => {
    const { fetchAuthQuery } = setupJwtCache({ cookieJwt: makeJwt(300) });
    fetchQueryMock.mockRejectedValueOnce(new Error("Server Error"));

    await expect(fetchAuthQuery(query)).rejects.toThrow("Server Error");
    expect(fetchQueryMock).toHaveBeenCalledTimes(1);
  });

  it("does not retry when the jwt was already freshly fetched", async () => {
    const { fetchAuthQuery } = setupJwtCache();
    fetchQueryMock.mockRejectedValueOnce(new Error("Unauthenticated"));

    await expect(fetchAuthQuery(query)).rejects.toThrow("Unauthenticated");
    expect(fetchQueryMock).toHaveBeenCalledTimes(1);
    expect(fetchQueryMock.mock.calls[0]?.[2]).toEqual({ token: FRESH_JWT });
  });
});
