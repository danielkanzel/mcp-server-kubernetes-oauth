import {
  createAccessTokenVerifier,
  createAuthentikAuthMiddleware,
  installAuthentikRoutes,
  readAuthentikOAuthConfig,
  type AuthentikOAuthConfig,
} from "../src/utils/authentik-oauth.js";
import express from "express";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { Request, Response } from "express";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWTVerifyGetKey,
} from "jose";
import { afterEach, beforeAll, describe, expect, test, vi } from "vitest";

const ISSUER = "https://auth.example.com/application/o/mcp/";
const CLIENT_ID = "mcp-public-client";

const ENV_KEYS = [
  "AUTHENTIK_ISSUER",
  "AUTHENTIK_CLIENT_ID",
  "AUTHENTIK_CLIENT_SECRET",
  "AUTHENTIK_AUDIENCE",
  "AUTHENTIK_SCOPES",
  "AUTHENTIK_REQUIRED_SCOPES",
  "AUTHENTIK_REQUIRED_GROUPS",
  "AUTHENTIK_JWKS_URI",
  "MCP_PUBLIC_URL",
  "MCP_AUTH_TOKEN",
  "HOST",
  "PORT",
  "MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL",
] as const;

const originalEnv = new Map<string, string | undefined>();

beforeAll(() => {
  for (const key of ENV_KEYS) {
    originalEnv.set(key, process.env[key]);
  }
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    const value = originalEnv.get(key);
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
});

function baseConfig(overrides: Partial<AuthentikOAuthConfig> = {}): AuthentikOAuthConfig {
  return {
    issuer: ISSUER,
    clientId: CLIENT_ID,
    audience: CLIENT_ID,
    publicUrl: new URL("http://localhost:3000"),
    resourceUrl: new URL("http://localhost:3000/mcp"),
    scopes: ["openid", "profile", "email"],
    requiredScopes: [],
    requiredGroups: [],
    authorizationEndpoint: `${ISSUER}authorize/`,
    tokenEndpoint: `${ISSUER}token/`,
    jwksUri: `${ISSUER}jwks/`,
    introspectionEndpoint: `${ISSUER}token/introspect/`,
    revocationEndpoint: `${ISSUER}revoke/`,
    ...overrides,
  };
}

let privateKey: CryptoKey;
let jwks: JWTVerifyGetKey;

beforeAll(async () => {
  const keys = await generateKeyPair("RS256", { extractable: true });
  privateKey = keys.privateKey;
  const jwk = await exportJWK(keys.publicKey);
  jwk.alg = "RS256";
  jwk.kid = "test-key";
  jwk.use = "sig";
  jwks = createLocalJWKSet({ keys: [jwk] });
});

async function signToken(
  claims: Record<string, unknown> = {},
  options: { audience?: string; issuer?: string; expiresIn?: string; typ?: string } = {}
): Promise<string> {
  return new SignJWT({ scope: "openid profile email", groups: ["k8s"], ...claims })
    .setProtectedHeader({ alg: "RS256", kid: "test-key", typ: options.typ ?? "at+jwt" })
    .setIssuer(options.issuer ?? ISSUER)
    .setAudience(options.audience ?? CLIENT_ID)
    .setSubject("alice")
    .setIssuedAt()
    .setExpirationTime(options.expiresIn ?? "10m")
    .sign(privateKey);
}

function mockRes(): Response & {
  statusCode: number;
  headers: Record<string, string>;
  body: unknown;
  finished: Promise<void>;
} {
  let finish = () => {};
  const finished = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const res = {
    statusCode: 200,
    headers: {} as Record<string, string>,
    body: undefined as unknown,
    finished,
    setHeader(name: string, value: string) {
      res.headers[name.toLowerCase()] = value;
      return res;
    },
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(data: unknown) {
      res.body = data;
      finish();
      return res;
    },
    sendStatus(code: number) {
      res.statusCode = code;
      finish();
      return res;
    },
  };
  return res as unknown as Response & {
    statusCode: number;
    headers: Record<string, string>;
    body: unknown;
    finished: Promise<void>;
  };
}

function mockReq(headers: Record<string, string> = {}): Request {
  return { headers, socket: { remoteAddress: "127.0.0.1" } } as unknown as Request;
}

async function withApp(
  setup: (app: express.Express) => void,
  run: (baseUrl: string) => Promise<void>
): Promise<void> {
  const app = express();
  setup(app);
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await run(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    );
  }
}

describe("readAuthentikOAuthConfig", () => {
  test("returns null when AUTHENTIK_ISSUER is unset", () => {
    delete process.env.AUTHENTIK_ISSUER;
    expect(readAuthentikOAuthConfig("/mcp")).toBeNull();
  });

  test("requires a client id and normalizes the issuer slash", () => {
    process.env.AUTHENTIK_ISSUER = "https://auth.example.com/application/o/mcp";
    expect(() => readAuthentikOAuthConfig("/mcp")).toThrow(/AUTHENTIK_CLIENT_ID/);

    process.env.AUTHENTIK_CLIENT_ID = CLIENT_ID;
    process.env.MCP_PUBLIC_URL = "http://localhost:3000";
    const config = readAuthentikOAuthConfig("/mcp");
    expect(config?.issuer).toBe(ISSUER);
    expect(config?.jwksUri).toBe(`${ISSUER}jwks/`);
    expect(config?.authorizationEndpoint).toBe(`${ISSUER}authorize/`);
    expect(config?.resourceUrl.href).toBe("http://localhost:3000/mcp");
    expect(config?.audience).toBe(CLIENT_ID);
  });

  test("rejects a public URL that is not https off localhost", () => {
    process.env.AUTHENTIK_ISSUER = ISSUER;
    process.env.AUTHENTIK_CLIENT_ID = CLIENT_ID;
    process.env.MCP_PUBLIC_URL = "http://mcp.example.com";
    expect(() => readAuthentikOAuthConfig("/mcp")).toThrow(/https/);
  });

  test("requires MCP_PUBLIC_URL when binding all interfaces", () => {
    process.env.AUTHENTIK_ISSUER = ISSUER;
    process.env.AUTHENTIK_CLIENT_ID = CLIENT_ID;
    delete process.env.MCP_PUBLIC_URL;
    process.env.HOST = "0.0.0.0";
    expect(() => readAuthentikOAuthConfig("/mcp")).toThrow(/MCP_PUBLIC_URL/);
  });
});

describe("Authentik access tokens", () => {
  test("accepts a JWT signed by the configured issuer for the client id", async () => {
    const config = baseConfig();
    const token = await signToken();
    const auth = await createAccessTokenVerifier(config, { jwks })(token);
    expect(auth.extra?.sub).toBe("alice");
    expect(auth.clientId).toBe(CLIENT_ID);
    expect(auth.scopes).toContain("openid");
    expect(auth.extra?.groups).toEqual(["k8s"]);
  });

  test("rejects a token for a different audience or issuer", async () => {
    const verify = createAccessTokenVerifier(baseConfig(), { jwks });
    await expect(verify(await signToken({}, { audience: "other-client" }))).rejects.toThrow(
      /audience/
    );
    await expect(
      verify(await signToken({}, { issuer: "https://auth.example.com/application/o/other/" }))
    ).rejects.toThrow(/issuer|iss/i);
  });

  test("rejects an expired token and a missing required group", async () => {
    const verify = createAccessTokenVerifier(
      baseConfig({ requiredGroups: ["k8s-admins"] }),
      { jwks }
    );
    await expect(verify(await signToken({}, { expiresIn: "-2m" }))).rejects.toThrow(/expir|exp/i);
    await expect(verify(await signToken({ groups: ["others"] }))).rejects.toThrow(/group/i);
  });

  test("introspects an opaque token when a client secret is configured", async () => {
    const config = baseConfig({ clientSecret: "secret" });
    const fetchFn = vi.fn(async () =>
      new Response(
        JSON.stringify({
          active: true,
          scope: "openid email",
          exp: Math.floor(Date.now() / 1000) + 300,
          sub: "bob",
          iss: ISSUER,
          aud: CLIENT_ID,
          client_id: CLIENT_ID,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      )
    );
    const auth = await createAccessTokenVerifier(config, {
      jwks,
      fetchFn: fetchFn as unknown as typeof fetch,
    })("opaque-token");
    expect(auth.extra?.sub).toBe("bob");
    expect(fetchFn).toHaveBeenCalledOnce();
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(config.introspectionEndpoint);
    expect(String(init.body)).toContain("client_secret=secret");
  });
});

describe("Authentik auth middleware", () => {
  test("returns 401 with protected-resource metadata when the bearer token is missing", async () => {
    const middleware = createAuthentikAuthMiddleware(baseConfig(), async () => {
      throw new Error("should not verify");
    });
    const res = mockRes();
    middleware(mockReq(), res, vi.fn());
    await res.finished;
    expect(res.statusCode).toBe(401);
    expect(res.headers["www-authenticate"]).toContain(
      'resource_metadata="http://localhost:3000/.well-known/oauth-protected-resource/mcp"'
    );
  });

  test("accepts a valid bearer token and a configured static token", async () => {
    const config = baseConfig();
    const token = await signToken();
    const middleware = createAuthentikAuthMiddleware(
      config,
      createAccessTokenVerifier(config, { jwks })
    );
    const res = mockRes();
    let authed = false;
    middleware(
      mockReq({ authorization: `Bearer ${token}` }),
      res,
      () => {
        authed = true;
      }
    );
    await vi.waitFor(() => expect(authed).toBe(true));

    process.env.MCP_AUTH_TOKEN = "static-secret";
    const next = vi.fn();
    middleware(mockReq({ "x-mcp-auth": "static-secret" }), mockRes(), next);
    expect(next).toHaveBeenCalled();
  });
});

describe("Authentik discovery routes", () => {
  test("advertises Authentik endpoints and the pre-registered client", async () => {
    const config = baseConfig();
    await withApp(
      (app) => installAuthentikRoutes(app, config),
      async (baseUrl) => {
        const metadata = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
        expect(metadata.status).toBe(200);
        const body = await metadata.json();
        expect(body.issuer).toBe("http://localhost:3000");
        expect(body.authorization_endpoint).toBe(`${ISSUER}authorize/`);
        expect(body.token_endpoint).toBe(`${ISSUER}token/`);
        expect(body.registration_endpoint).toBe("http://localhost:3000/register");
        expect(body.code_challenge_methods_supported).toEqual(["S256"]);

        const prm = await fetch(
          `${baseUrl}/.well-known/oauth-protected-resource/mcp`
        );
        expect(prm.status).toBe(200);
        const prmBody = await prm.json();
        expect(prmBody.resource).toBe("http://localhost:3000/mcp");
        expect(prmBody.authorization_servers).toEqual(["http://localhost:3000"]);

        const registered = await fetch(`${baseUrl}/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            redirect_uris: ["http://127.0.0.1:54321/callback"],
            token_endpoint_auth_method: "none",
            client_name: "Cursor",
          }),
        });
        expect(registered.status).toBe(201);
        const client = await registered.json();
        expect(client.client_id).toBe(CLIENT_ID);
        expect(client.client_secret).toBeUndefined();
        expect(client.redirect_uris).toEqual(["http://127.0.0.1:54321/callback"]);

        const rejected = await fetch(`${baseUrl}/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ redirect_uris: ["javascript:alert(1)"] }),
        });
        expect(rejected.status).toBe(400);
      }
    );
  });
});
