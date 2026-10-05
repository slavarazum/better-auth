import { describe, expect, it } from "vitest";
import { betterAuth } from "better-auth/minimal";
import { memoryAdapter } from "better-auth/adapters/memory";
import type { MemoryDB } from "better-auth/adapters/memory";
import { genericOAuth } from "better-auth/plugins";
import { magicLink } from "better-auth/plugins/magic-link";
import { createAuthClient } from "better-auth/client";
import { genericOAuthClient } from "better-auth/client/plugins";
import { crossDomain } from "./index.js";
import { crossDomainClient, getCookie, getSetCookie } from "./client.js";

const SITE_URL = "https://myapp.example.com";
const AUTH_BASE_URL = "http://localhost:3000";
const BASE_PATH = "/api/auth";

describe("crossDomain plugin", async () => {
  let capturedMagicLinkUrl = "";

  const db: MemoryDB = {
    user: [],
    session: [],
    account: [],
    verification: [],
  };

  const auth = betterAuth({
    baseURL: AUTH_BASE_URL,
    basePath: BASE_PATH,
    secret: "test-secret-at-least-thirty-two-characters-long",
    database: memoryAdapter(db),
    emailAndPassword: {
      enabled: true,
      requireEmailVerification: false,
    },
    plugins: [
      magicLink({
        sendMagicLink: async ({ url }) => {
          capturedMagicLinkUrl = url;
        },
      }),
      genericOAuth({
        config: [
          {
            providerId: "example-oauth",
            clientId: "test-client-id",
            clientSecret: "test-client-secret",
            authorizationUrl: "https://provider.example.com/oauth/authorize",
            tokenUrl: "https://provider.example.com/oauth/token",
          },
        ],
      }),
      crossDomain({ siteUrl: SITE_URL }),
    ],
  });

  const post = (
    path: string,
    body: Record<string, unknown>,
    extraHeaders?: Record<string, string>
  ) =>
    auth.handler(
      new Request(`${AUTH_BASE_URL}${BASE_PATH}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...extraHeaders },
        body: JSON.stringify(body),
      })
    );

  await post("/sign-up/email", {
    email: "test@example.com",
    password: "testpassword123",
    name: "Test User",
  });

  describe("callbackURL defaulting for magic-link", () => {
    it("injects siteUrl when callbackURL is absent", async () => {
      capturedMagicLinkUrl = "";
      await post("/sign-in/magic-link", { email: "test@example.com" });
      const url = new URL(capturedMagicLinkUrl);
      expect(url.searchParams.get("callbackURL")).toBe(SITE_URL);
    });

    it("rewrites relative callbackURL to absolute using siteUrl", async () => {
      capturedMagicLinkUrl = "";
      await post("/sign-in/magic-link", {
        email: "test@example.com",
        callbackURL: "/dashboard",
      });
      const url = new URL(capturedMagicLinkUrl);
      expect(url.searchParams.get("callbackURL")).toBe(`${SITE_URL}/dashboard`);
    });

    it("preserves absolute callbackURL", async () => {
      capturedMagicLinkUrl = "";
      await post("/sign-in/magic-link", {
        email: "test@example.com",
        callbackURL: "https://other.example.com/callback",
      });
      const url = new URL(capturedMagicLinkUrl);
      expect(url.searchParams.get("callbackURL")).toBe(
        "https://other.example.com/callback"
      );
    });
  });

  describe("callbackURL defaulting for oauth2", () => {
    it("injects siteUrl when callbackURL is absent", async () => {
      const response = await post("/sign-in/oauth2", {
        providerId: "example-oauth",
        disableRedirect: true,
      });
      const { url } = (await response.json()) as { url: string };
      const state = new URL(url).searchParams.get("state");
      const verification = db.verification.find(
        (entry) => entry.identifier === state
      );
      expect(verification).toBeDefined();
      expect(JSON.parse(verification!.value).callbackURL).toBe(SITE_URL);
    });

    it("rewrites relative callbackURL to absolute using siteUrl", async () => {
      const response = await post("/sign-in/oauth2", {
        providerId: "example-oauth",
        callbackURL: "/dashboard",
        disableRedirect: true,
      });
      const { url } = (await response.json()) as { url: string };
      const state = new URL(url).searchParams.get("state");
      const verification = db.verification.find(
        (entry) => entry.identifier === state
      );
      expect(verification).toBeDefined();
      expect(JSON.parse(verification!.value).callbackURL).toBe(
        `${SITE_URL}/dashboard`
      );
    });
  });

  describe("no callbackURL injection for email sign-in", () => {
    it("does not redirect when callbackURL is absent", async () => {
      const response = await post("/sign-in/email", {
        email: "test@example.com",
        password: "testpassword123",
      });
      expect(response.status).not.toBe(302);
    });
  });
});

describe("crossDomain preventOAuthCSRF", () => {
  const createAuth = (preventOAuthCSRF?: boolean) => {
    let magicLinkUrl = "";
    let users = 0;
    const auth = betterAuth({
      baseURL: AUTH_BASE_URL,
      basePath: BASE_PATH,
      secret: "test-secret-at-least-thirty-two-characters-long",
      database: memoryAdapter({
        user: [],
        session: [],
        account: [],
        verification: [],
      }),
      plugins: [
        magicLink({
          sendMagicLink: async ({ url }) => {
            magicLinkUrl = url;
          },
        }),
        genericOAuth({
          config: [
            {
              providerId: "example-oauth",
              clientId: "test-client-id",
              clientSecret: "test-client-secret",
              authorizationUrl: "https://provider.example.com/oauth/authorize",
              tokenUrl: "https://provider.example.com/oauth/token",
              getToken: async () => ({ accessToken: "access-token" }),
              getUserInfo: async () => {
                users++;
                return {
                  id: `user-${users}`,
                  email: `user-${users}@example.com`,
                  name: "Test User",
                  emailVerified: true,
                };
              },
            },
          ],
        }),
        crossDomain({ siteUrl: SITE_URL, preventOAuthCSRF }),
      ],
    });

    // Sends cookies the way crossDomainClient does, in Better-Auth-Cookie
    const post = (path: string, body: Record<string, unknown>, cookie = "") =>
      auth.handler(
        new Request(`${AUTH_BASE_URL}${BASE_PATH}${path}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Better-Auth-Cookie": cookie,
          },
          body: JSON.stringify(body),
        })
      );
    const ott = (response: Response) =>
      new URL(response.headers.get("location")!).searchParams.get("ott");
    // Plays the provider: returns from its authorization url to the callback
    const finishOAuth = async (authorizationUrl: string) => {
      const state = new URL(authorizationUrl).searchParams.get("state");
      return ott(
        await auth.handler(
          new Request(
            `${AUTH_BASE_URL}${BASE_PATH}/oauth2/callback/example-oauth?code=code&state=${state}`
          )
        )
      );
    };

    return {
      auth,
      finishOAuth,
      // Returns the token and the cookies the browser kept from sign-in
      signInWithOAuth: async () => {
        const response = await post("/sign-in/oauth2", {
          providerId: "example-oauth",
          disableRedirect: true,
        });
        const cookie = getCookie(
          getSetCookie(response.headers.get("set-better-auth-cookie")!)
        );
        const { url } = (await response.json()) as { url: string };
        return { token: await finishOAuth(url), cookie };
      },
      signInWithMagicLink: async () => {
        await post("/sign-in/magic-link", { email: "magic@example.com" });
        return ott(await auth.handler(new Request(magicLinkUrl)));
      },
      verify: (token: string | null, cookie?: string) =>
        post("/cross-domain/one-time-token/verify", { token }, cookie),
    };
  };

  it("exchanges OAuth tokens in any browser by default", async () => {
    const { signInWithOAuth, verify } = createAuth();
    const { token } = await signInWithOAuth();
    expect((await verify(token)).status).toBe(200);
  });

  it("exchanges an OAuth token only in the browser that started it", async () => {
    const { signInWithOAuth, verify } = createAuth(true);
    const own = await signInWithOAuth();
    const other = await signInWithOAuth();
    // Failed attempts must neither spend nor unbind the token
    for (const cookie of [undefined, other.cookie, undefined]) {
      expect((await verify(own.token, cookie)).status).toBe(400);
    }
    expect((await verify(own.token, own.cookie)).status).toBe(200);
  });

  it("exchanges magic link tokens in any browser", async () => {
    const { signInWithMagicLink, verify } = createAuth(true);
    const token = await signInWithMagicLink();
    expect((await verify(token)).status).toBe(200);
  });

  it("signs in through crossDomainClient", async () => {
    const { auth, finishOAuth } = createAuth(true);
    const storage = new Map<string, string>();
    const client = createAuthClient({
      baseURL: `${AUTH_BASE_URL}${BASE_PATH}`,
      plugins: [
        genericOAuthClient(),
        crossDomainClient({
          storage: {
            getItem: (key) => storage.get(key) ?? null,
            setItem: (key, value) => storage.set(key, value),
          },
        }),
      ],
      fetchOptions: {
        customFetchImpl: (input, init) =>
          auth.handler(new Request(input, init)),
      },
    });
    const { data } = await client.signIn.oauth2({
      providerId: "example-oauth",
      disableRedirect: true,
    });
    const token = await finishOAuth(data!.url);
    const { data: session } = await client.crossDomain.oneTimeToken.verify({
      token: token!,
    });
    expect(session?.session).toBeDefined();
  });
});
