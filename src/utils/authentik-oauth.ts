import express, { NextFunction, Request, Response } from "express";
import {
  createRemoteJWKSet,
  decodeProtectedHeader,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import {
  createAuthMiddleware,
  isAuthEnabled,
  matchStaticAuthToken,
} from "./auth.js";

const DEFAULT_SCOPES = ["openid", "profile", "email"];
const ALLOWED_ALGS = ["RS256", "PS256", "ES256", "ES384"] as const;
const LOCAL_PUBLIC_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

/**
 * Authentik OAuth for the HTTP transports.
 *
 * The MCP server is the resource server. Authentik is the authorization server
 * that actually issues tokens. Open-source Authentik has no dynamic client
 * registration, so this process also publishes OAuth metadata and a /register
 * endpoint that hands every MCP client the one public client pre-created in
 * Authentik. Authorize and token requests still go to Authentik.
 *
 * Access tokens are verified locally against Authentik's JWKS. Authentik puts
 * the OAuth client id in the `aud` claim (it does not implement RFC 8707
 * resource indicators).
 */

export interface AuthentikOAuthConfig {
  /** Authentik issuer, including the trailing slash. Must match the token `iss`. */
  issuer: string;
  clientId: string;
  /** Claim value expected in `aud` (defaults to clientId). */
  audience: string;
  clientSecret?: string;
  /** External origin of this MCP server, used as the metadata issuer. */
  publicUrl: URL;
  /** MCP endpoint clients connect to, e.g. http://host:3000/mcp. */
  resourceUrl: URL;
  /** Scopes advertised to clients. */
  scopes: string[];
  /** Scopes the access token must contain. Empty means do not check. */
  requiredScopes: string[];
  /** Authentik `groups` claim values the token must contain. Empty means do not check. */
  requiredGroups: string[];
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  introspectionEndpoint: string;
  revocationEndpoint: string;
}

export class AuthentikOAuthConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthentikOAuthConfigError";
  }
}

export class TokenVerificationError extends Error {
  readonly status: 401 | 403;
  readonly oauthError: "invalid_token" | "insufficient_scope";

  constructor(
    status: 401 | 403,
    oauthError: "invalid_token" | "insufficient_scope",
    message: string
  ) {
    super(message);
    this.name = "TokenVerificationError";
    this.status = status;
    this.oauthError = oauthError;
  }
}

export function readAuthentikOAuthConfig(
  resourcePath: string
): AuthentikOAuthConfig | null {
  const issuerRaw = process.env.AUTHENTIK_ISSUER?.trim();
  if (!issuerRaw) {
    return null;
  }

  const clientId = process.env.AUTHENTIK_CLIENT_ID?.trim();
  if (!clientId) {
    throw new AuthentikOAuthConfigError(
      "AUTHENTIK_CLIENT_ID is required when AUTHENTIK_ISSUER is set"
    );
  }

  const issuer = normalizeIssuer(issuerRaw);
  const publicUrl = readPublicUrl();
  const resourceUrl = new URL(
    resourcePath.startsWith("/") ? resourcePath : `/${resourcePath}`,
    publicUrl
  );
  const audience = process.env.AUTHENTIK_AUDIENCE?.trim() || clientId;
  const clientSecret = process.env.AUTHENTIK_CLIENT_SECRET?.trim() || undefined;

  return {
    issuer,
    clientId,
    audience,
    clientSecret,
    publicUrl,
    resourceUrl,
    scopes: splitList(process.env.AUTHENTIK_SCOPES, DEFAULT_SCOPES),
    requiredScopes: splitList(process.env.AUTHENTIK_REQUIRED_SCOPES, []),
    requiredGroups: splitList(process.env.AUTHENTIK_REQUIRED_GROUPS, []),
    authorizationEndpoint:
      process.env.AUTHENTIK_AUTHORIZATION_ENDPOINT?.trim() ||
      joinIssuer(issuer, "authorize/"),
    tokenEndpoint:
      process.env.AUTHENTIK_TOKEN_ENDPOINT?.trim() || joinIssuer(issuer, "token/"),
    jwksUri: process.env.AUTHENTIK_JWKS_URI?.trim() || joinIssuer(issuer, "jwks/"),
    introspectionEndpoint: joinIssuer(issuer, "token/introspect/"),
    revocationEndpoint: joinIssuer(issuer, "revoke/"),
  };
}

export interface HttpAuth {
  middleware: express.RequestHandler;
  mode: "authentik" | "static" | "none";
  issuer?: string;
  acceptsStaticToken: boolean;
}

/**
 * Install Authentik discovery routes when configured, and return the
 * middleware that protects MCP endpoints.
 */
export function configureHttpAuth(
  app: express.Express,
  resourcePath: string
): HttpAuth {
  const config = readAuthentikOAuthConfig(resourcePath);
  if (!config) {
    return {
      middleware: createAuthMiddleware(),
      mode: isAuthEnabled() ? "static" : "none",
      acceptsStaticToken: isAuthEnabled(),
    };
  }

  installAuthentikRoutes(app, config);
  return {
    middleware: createAuthentikAuthMiddleware(config),
    mode: "authentik",
    issuer: config.issuer,
    acceptsStaticToken: isAuthEnabled(),
  };
}

export function protectedResourceMetadataUrl(resourceUrl: URL): string {
  const path =
    resourceUrl.pathname && resourceUrl.pathname !== "/"
      ? resourceUrl.pathname
      : "";
  return new URL(`/.well-known/oauth-protected-resource${path}`, resourceUrl)
    .href;
}

export function authorizationServerMetadata(config: AuthentikOAuthConfig) {
  return {
    issuer: config.publicUrl.origin,
    authorization_endpoint: config.authorizationEndpoint,
    token_endpoint: config.tokenEndpoint,
    registration_endpoint: new URL("/register", config.publicUrl).href,
    revocation_endpoint: config.revocationEndpoint,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint_auth_methods_supported: ["none"],
    scopes_supported: config.scopes,
  };
}

export function protectedResourceMetadata(config: AuthentikOAuthConfig) {
  return {
    resource: config.resourceUrl.href,
    authorization_servers: [config.publicUrl.origin],
    scopes_supported: config.scopes,
    bearer_methods_supported: ["header"],
    resource_name: "Kubernetes MCP Server",
  };
}

export function installAuthentikRoutes(
  app: express.Express,
  config: AuthentikOAuthConfig
): void {
  app.use((req, res, next) => {
    setOauthCors(res);
    if (req.method === "OPTIONS") {
      res.sendStatus(204);
      return;
    }
    next();
  });

  const prm = protectedResourceMetadata(config);
  const sendPrm = (_req: Request, res: Response) => {
    res.setHeader("Cache-Control", "public, max-age=300");
    res.json(prm);
  };
  app.get("/.well-known/oauth-protected-resource", sendPrm);
  app.get(
    `/.well-known/oauth-protected-resource${config.resourceUrl.pathname}`,
    sendPrm
  );
  app.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.setHeader("Cache-Control", "public, max-age=300");
    res.json(authorizationServerMetadata(config));
  });

  const register = express.Router();
  register.use(express.json({ limit: "16kb" }));
  register.post("/", (req, res) => {
    if (!allowRegistration(req)) {
      res.setHeader("Cache-Control", "no-store");
      res.status(429).json({
        error: "too_many_requests",
        error_description: "Too many client registration requests",
      });
      return;
    }
    try {
      const redirectUris = parseRedirectUris(req.body);
      const clientName = readClientName(req.body);
      res.setHeader("Cache-Control", "no-store");
      res.status(201).json({
        client_id: config.clientId,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        redirect_uris: redirectUris,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        ...(clientName ? { client_name: clientName } : {}),
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Invalid client metadata";
      res.setHeader("Cache-Control", "no-store");
      res.status(400).json({
        error: "invalid_client_metadata",
        error_description: message,
      });
    }
  });
  register.use(
    (
      err: unknown,
      _req: Request,
      res: Response,
      next: NextFunction
    ) => {
      if (!err) {
        next();
        return;
      }
      res.setHeader("Cache-Control", "no-store");
      res.status(400).json({
        error: "invalid_client_metadata",
        error_description: "Request body must be JSON",
      });
    }
  );
  app.use("/register", register);
}

export type AccessTokenVerifier = (token: string) => Promise<AuthInfo>;

export function createAccessTokenVerifier(
  config: AuthentikOAuthConfig,
  deps: { jwks?: JWTVerifyGetKey; fetchFn?: typeof fetch } = {}
): AccessTokenVerifier {
  const jwks = deps.jwks ?? createRemoteJWKSet(new URL(config.jwksUri));
  const fetchFn = deps.fetchFn ?? fetch;

  return async (token: string): Promise<AuthInfo> => {
    if (token.split(".").length === 3) {
      return verifyJwt(token, config, jwks);
    }
    if (!config.clientSecret) {
      throw new TokenVerificationError(
        401,
        "invalid_token",
        "Invalid token"
      );
    }
    return introspectOpaqueToken(token, config, fetchFn);
  };
}

export function createAuthentikAuthMiddleware(
  config: AuthentikOAuthConfig,
  verify: AccessTokenVerifier = createAccessTokenVerifier(config)
): express.RequestHandler {
  const resourceMetadataUrl = protectedResourceMetadataUrl(config.resourceUrl);

  return (req, res, next) => {
    if (matchStaticAuthToken(req.headers["x-mcp-auth"]) === "ok") {
      next();
      return;
    }

    const header = req.headers.authorization;
    if (!header) {
      unauthorized(res, resourceMetadataUrl, config, 401, "invalid_token", "Missing Authorization header");
      return;
    }

    const match = /^Bearer\s+(\S+)$/i.exec(header);
    if (!match) {
      unauthorized(
        res,
        resourceMetadataUrl,
        config,
        401,
        "invalid_token",
        "Invalid Authorization header format, expected 'Bearer TOKEN'"
      );
      return;
    }

    verify(match[1])
      .then((authInfo) => {
        (req as Request & { auth?: AuthInfo }).auth = authInfo;
        next();
      })
      .catch((error: unknown) => {
        if (error instanceof TokenVerificationError) {
          if (error.status === 401) {
            console.error(`Authentik token rejected: ${error.message}`);
          }
          unauthorized(
            res,
            resourceMetadataUrl,
            config,
            error.status,
            error.oauthError,
            error.status === 401 ? "Invalid token" : error.message
          );
          return;
        }
        console.error("Authentik token verification failed:", error);
        unauthorized(
          res,
          resourceMetadataUrl,
          config,
          401,
          "invalid_token",
          "Invalid token"
        );
      });
  };
}

async function verifyJwt(
  token: string,
  config: AuthentikOAuthConfig,
  jwks: JWTVerifyGetKey
): Promise<AuthInfo> {
  let headerTyp: string | undefined;
  try {
    const header = decodeProtectedHeader(token);
    headerTyp = typeof header.typ === "string" ? header.typ : undefined;
  } catch {
    throw new TokenVerificationError(401, "invalid_token", "Malformed token");
  }

  let payload: JWTPayload;
  try {
    const verified = await jwtVerify(token, jwks, {
      issuer: config.issuer,
      algorithms: [...ALLOWED_ALGS],
      clockTolerance: 60,
      ...(headerTyp ? { typ: headerTyp } : {}),
    });
    payload = verified.payload;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid token";
    throw new TokenVerificationError(401, "invalid_token", message);
  }

  if (!payload.sub) {
    throw new TokenVerificationError(401, "invalid_token", "Token has no subject");
  }
  if (typeof payload.exp !== "number") {
    throw new TokenVerificationError(401, "invalid_token", "Token has no expiration");
  }
  if (!audienceMatches(payload, config.audience)) {
    throw new TokenVerificationError(401, "invalid_token", "Invalid token audience");
  }

  const scopes = readScopes(payload);
  assertScopesAndGroups(config, scopes, readGroups(payload));

  return {
    token,
    clientId: typeof payload.azp === "string" ? payload.azp : config.clientId,
    scopes,
    expiresAt: payload.exp,
    extra: {
      sub: payload.sub,
      groups: readGroups(payload),
    },
  };
}

async function introspectOpaqueToken(
  token: string,
  config: AuthentikOAuthConfig,
  fetchFn: typeof fetch
): Promise<AuthInfo> {
  const body = new URLSearchParams({
    token,
    client_id: config.clientId,
    client_secret: config.clientSecret ?? "",
  });
  let response: Awaited<ReturnType<typeof fetch>>;
  try {
    response = await fetchFn(config.introspectionEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "introspection failed";
    throw new TokenVerificationError(401, "invalid_token", message);
  }

  if (!response.ok) {
    await response.body?.cancel();
    throw new TokenVerificationError(401, "invalid_token", "Token introspection failed");
  }

  const data = (await response.json()) as {
    active?: boolean;
    scope?: string;
    exp?: number;
    sub?: string;
    username?: string;
    iss?: string;
    aud?: string | string[];
    client_id?: string;
    groups?: unknown;
  };

  if (!data.active) {
    throw new TokenVerificationError(401, "invalid_token", "Token is inactive");
  }
  if (data.iss && data.iss !== config.issuer) {
    throw new TokenVerificationError(401, "invalid_token", "Invalid token issuer");
  }
  if (data.aud !== undefined && !audienceMatches(data, config.audience)) {
    throw new TokenVerificationError(401, "invalid_token", "Invalid token audience");
  }
  if (data.client_id && data.client_id !== config.clientId) {
    throw new TokenVerificationError(401, "invalid_token", "Invalid token audience");
  }
  if (data.aud === undefined && data.client_id !== config.clientId) {
    throw new TokenVerificationError(401, "invalid_token", "Invalid token audience");
  }
  if (typeof data.exp !== "number" || data.exp < Date.now() / 1000) {
    throw new TokenVerificationError(401, "invalid_token", "Token has expired");
  }

  const sub = data.sub || data.username;
  if (!sub) {
    throw new TokenVerificationError(401, "invalid_token", "Token has no subject");
  }

  const scopes = typeof data.scope === "string" ? data.scope.split(" ").filter(Boolean) : [];
  assertScopesAndGroups(config, scopes, readGroups(data));

  return {
    token,
    clientId: data.client_id || config.clientId,
    scopes,
    expiresAt: data.exp,
    extra: { sub, groups: readGroups(data) },
  };
}

function assertScopesAndGroups(
  config: AuthentikOAuthConfig,
  scopes: string[],
  groups: string[]
): void {
  const missingScope = config.requiredScopes.find((scope) => !scopes.includes(scope));
  if (missingScope) {
    throw new TokenVerificationError(
      403,
      "insufficient_scope",
      "Insufficient scope"
    );
  }
  const missingGroup = config.requiredGroups.find((group) => !groups.includes(group));
  if (missingGroup) {
    throw new TokenVerificationError(
      403,
      "insufficient_scope",
      "Required group is missing"
    );
  }
}

function audienceMatches(
  payload: { aud?: unknown; azp?: unknown },
  audience: string
): boolean {
  const aud = payload.aud;
  if (typeof aud === "string") {
    return aud === audience;
  }
  if (Array.isArray(aud)) {
    return aud.includes(audience);
  }
  return typeof payload.azp === "string" && payload.azp === audience;
}

function readScopes(payload: JWTPayload): string[] {
  if (typeof payload.scope === "string") {
    return payload.scope.split(" ").filter(Boolean);
  }
  if (Array.isArray(payload.scp)) {
    return payload.scp.filter((scope): scope is string => typeof scope === "string");
  }
  return [];
}

function readGroups(payload: object): string[] {
  const groups = (payload as { groups?: unknown }).groups;
  if (Array.isArray(groups)) {
    return groups.filter((group): group is string => typeof group === "string");
  }
  if (typeof groups === "string" && groups.length > 0) {
    return groups.split(" ").filter(Boolean);
  }
  return [];
}

function unauthorized(
  res: Response,
  resourceMetadataUrl: string,
  config: AuthentikOAuthConfig,
  status: 401 | 403,
  oauthError: string,
  description: string
): void {
  let header = `Bearer error="${oauthError}", error_description="${description}", resource_metadata="${resourceMetadataUrl}"`;
  if (config.requiredScopes.length > 0) {
    header += `, scope="${config.requiredScopes.join(" ")}"`;
  }
  res.setHeader("WWW-Authenticate", header);
  res.status(status).json({
    error: oauthError,
    error_description: description,
  });
}

function setOauthCors(res: Response): void {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Expose-Headers",
    "WWW-Authenticate, Mcp-Session-Id"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Session-Id, Last-Event-ID, X-MCP-AUTH"
  );
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
}

const registrationHits = new Map<string, { count: number; resetAt: number }>();

function allowRegistration(req: Request): boolean {
  const ip = req.socket?.remoteAddress || "unknown";
  const now = Date.now();
  const current = registrationHits.get(ip);
  if (!current || current.resetAt < now) {
    registrationHits.set(ip, { count: 1, resetAt: now + 60 * 60 * 1000 });
    return true;
  }
  current.count += 1;
  return current.count <= 30;
}

function parseRedirectUris(body: unknown): string[] {
  if (!body || typeof body !== "object") {
    throw new Error("Client metadata must be a JSON object");
  }
  const uris = (body as { redirect_uris?: unknown }).redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0) {
    throw new Error("redirect_uris must be a non-empty array");
  }
  const parsed: string[] = [];
  for (const uri of uris) {
    if (typeof uri !== "string" || uri.length > 2048) {
      throw new Error("redirect_uris must contain URL strings");
    }
    let url: URL;
    try {
      url = new URL(uri);
    } catch {
      throw new Error(`Invalid redirect URI: ${uri}`);
    }
    if (
      url.protocol === "javascript:" ||
      url.protocol === "data:" ||
      url.protocol === "vbscript:"
    ) {
      throw new Error("Redirect URI scheme is not allowed");
    }
    parsed.push(uri);
  }
  return parsed;
}

function readClientName(body: unknown): string | undefined {
  if (!body || typeof body !== "object") {
    return undefined;
  }
  const name = (body as { client_name?: unknown }).client_name;
  if (typeof name !== "string") {
    return undefined;
  }
  const trimmed = name.trim();
  if (!trimmed || trimmed.length > 200) {
    return undefined;
  }
  return trimmed;
}

function normalizeIssuer(issuer: string): string {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    throw new AuthentikOAuthConfigError(
      `AUTHENTIK_ISSUER is not a valid URL: ${issuer}`
    );
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new AuthentikOAuthConfigError(
      "AUTHENTIK_ISSUER must use http or https"
    );
  }
  if (url.username || url.password) {
    throw new AuthentikOAuthConfigError(
      "AUTHENTIK_ISSUER must not contain credentials"
    );
  }
  if (url.search || url.hash) {
    throw new AuthentikOAuthConfigError(
      "AUTHENTIK_ISSUER must not contain a query or fragment"
    );
  }
  const href = url.href.endsWith("/") ? url.href : `${url.href}/`;
  return href;
}

function joinIssuer(issuer: string, suffix: string): string {
  return new URL(suffix, issuer).href;
}

function readPublicUrl(): URL {
  const configured = process.env.MCP_PUBLIC_URL?.trim();
  const host = process.env.HOST || "localhost";
  const port = process.env.PORT || "3000";
  let url: URL;
  if (configured) {
    try {
      url = new URL(configured);
    } catch {
      throw new AuthentikOAuthConfigError(
        `MCP_PUBLIC_URL is not a valid URL: ${configured}`
      );
    }
  } else if (host === "0.0.0.0" || host === "::" || host === "::0") {
    throw new AuthentikOAuthConfigError(
      "MCP_PUBLIC_URL is required when AUTHENTIK_ISSUER is set and HOST listens on all interfaces. " +
        "Set it to the external origin clients use, for example https://mcp.example.com"
    );
  } else {
    const hostname = host === "::1" ? "[::1]" : host;
    url = new URL(`http://${hostname}:${port}`);
  }

  if (url.username || url.password || url.search || url.hash) {
    throw new AuthentikOAuthConfigError(
      "MCP_PUBLIC_URL must not contain credentials, a query, or a fragment"
    );
  }
  if (url.pathname !== "/") {
    throw new AuthentikOAuthConfigError(
      "MCP_PUBLIC_URL must be an origin with no path, for example https://mcp.example.com"
    );
  }
  const insecureAllowed =
    process.env.MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL === "true" ||
    process.env.MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL === "1";
  if (
    url.protocol !== "https:" &&
    !LOCAL_PUBLIC_HOSTS.has(url.hostname) &&
    !insecureAllowed
  ) {
    throw new AuthentikOAuthConfigError(
      "MCP_PUBLIC_URL must use https (http is allowed only for localhost)"
    );
  }
  return url;
}

function splitList(value: string | undefined, fallback: string[]): string[] {
  if (value === undefined) {
    return fallback;
  }
  return value
    .split(/[,\s]+/)
    .map((part) => part.trim())
    .filter(Boolean);
}
