import { timingSafeEqual } from "crypto";
import { Request, Response, NextFunction } from "express";

/** Constant-time string comparison that prevents timing attacks (CWE-208). */
function timingSafeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Compare against itself to keep constant time, then return false
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

export type StaticAuthMatch = "disabled" | "ok" | "missing" | "malformed" | "mismatch";

/**
 * Compare an X-MCP-AUTH header value with MCP_AUTH_TOKEN.
 * "disabled" means the static token is not configured.
 */
export function matchStaticAuthToken(
  provided: string | string[] | undefined
): StaticAuthMatch {
  const authToken = process.env.MCP_AUTH_TOKEN;
  if (!authToken) {
    return "disabled";
  }
  if (provided === undefined) {
    return "missing";
  }
  if (Array.isArray(provided)) {
    return "malformed";
  }
  return timingSafeCompare(provided, authToken) ? "ok" : "mismatch";
}

/**
 * Authentication middleware for MCP HTTP transports.
 *
 * When the MCP_AUTH_TOKEN environment variable is set, this middleware
 * requires all requests to include a matching X-MCP-AUTH header.
 *
 * This provides a simple authentication mechanism for securing MCP endpoints
 * in cluster environments where full OAuth may be overkill.
 *
 * Example usage:
 *   Server: MCP_AUTH_TOKEN=my-secret-token
 *   Client: X-MCP-AUTH: my-secret-token
 */
export function createAuthMiddleware() {
  return (req: Request, res: Response, next: NextFunction): void => {
    switch (matchStaticAuthToken(req.headers["x-mcp-auth"])) {
      case "disabled":
      case "ok":
        next();
        return;
      case "missing":
        res.status(401).json({
          jsonrpc: "2.0",
          error: {
            code: -32001,
            message: "Unauthorized: X-MCP-AUTH header is required",
          },
          id: null,
        });
        return;
      case "malformed":
        res.status(401).json({
          jsonrpc: "2.0",
          error: {
            code: -32001,
            message: "Unauthorized: Only single X-MCP-AUTH header is allowed",
          },
          id: null,
        });
        return;
      case "mismatch":
        res.status(403).json({
          jsonrpc: "2.0",
          error: {
            code: -32002,
            message: "Forbidden: Invalid authentication token",
          },
          id: null,
        });
        return;
    }
  };
}

/**
 * Returns whether authentication is enabled (MCP_AUTH_TOKEN is set)
 */
export function isAuthEnabled(): boolean {
  return !!process.env.MCP_AUTH_TOKEN;
}
