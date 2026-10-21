import type { Express, Request, Response } from "express";
import { createServer, type Server, request as httpRequest } from "http";
import type { Socket } from "net";
import { URL } from "url";
import { config } from "./config";

/**
 * Register routes for the frontend server.
 *
 * The Node server is a thin "Backend-for-Frontend" (BFF):
 *   - All /api/* requests are proxied to the Rust api-gateway
 *   - All /ws WebSocket upgrade requests are tunneled to the Rust api-gateway
 *   - Static files are served by Express (configured in index.ts)
 */
export async function registerRoutes(app: Express): Promise<Server> {
  const API_GATEWAY_URL =
    process.env.API_GATEWAY_URL || config.apiGatewayUrl || "http://localhost:8080";
  const target = new URL(API_GATEWAY_URL);

  // Normalize any incoming /api shape to the gateway's canonical /api/v1/… form.
  // Express mounts this at "/api" and strips that prefix, so `req.url` here is
  // already relative (e.g. "/analysis/stats" or "/v1/auth/login").
  const normalizeToV1 = (url: string): string => {
    let p = url;
    if (p.startsWith("/api")) p = p.slice(4);
    if (p.startsWith("/v1")) p = p.slice(3);
    if (!p.startsWith("/")) p = `/${p}`;
    return `/api/v1${p}`;
  };

  app.use("/api", (req: Request, res: Response) => {
    const path = normalizeToV1(req.url);
    console.log(`[proxy] ${req.method} ${req.originalUrl} → ${API_GATEWAY_URL}${path}`);

    // Forward original headers; fix Host so changeOrigin semantics hold.
    const headers = { ...req.headers, host: target.host };

    const proxyReq = httpRequest(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || 80,
        method: req.method,
        path,
        headers,
      },
      (proxyRes) => {
        res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
        proxyRes.pipe(res);
      }
    );

    proxyReq.on("error", (err) => {
      console.error("[proxy] Error proxying request:", req.originalUrl, err.message);
      if (!res.headersSent) {
        res.writeHead(502, { "Content-Type": "application/json" });
      }
      res.end(
        JSON.stringify({
          error: "API Gateway unavailable",
          message:
            "The backend API gateway is not reachable. Please ensure it is running.",
        })
      );
    });

    // Pipe the raw request body straight through (works for GET and POST/PUT).
    req.pipe(proxyReq);
  });

  const httpServer = createServer(app);

  // Tunnel WebSocket upgrade requests (/ws) directly to the Rust API Gateway
  httpServer.on("upgrade", (req, socket: Socket, head) => {
    if (!req.url || !req.url.startsWith("/ws")) {
      return;
    }

    const proxyReq = httpRequest({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || 80,
      method: "GET",
      path: req.url,
      headers: {
        ...req.headers,
        host: target.host,
        Connection: "Upgrade",
        Upgrade: "websocket",
      },
    });

    proxyReq.on("upgrade", (proxyRes, proxySocket, proxyHead) => {
      let responseHeaders = `HTTP/1.1 ${proxyRes.statusCode || 101} ${proxyRes.statusMessage || "Switching Protocols"}\r\n`;
      for (const [key, value] of Object.entries(proxyRes.headers)) {
        if (value !== undefined) {
          if (Array.isArray(value)) {
            for (const v of value) {
              responseHeaders += `${key}: ${v}\r\n`;
            }
          } else {
            responseHeaders += `${key}: ${value}\r\n`;
          }
        }
      }
      responseHeaders += "\r\n";
      socket.write(responseHeaders);
      if (proxyHead && proxyHead.length > 0) {
        socket.write(proxyHead);
      }
      if (head && head.length > 0) {
        proxySocket.write(head);
      }
      proxySocket.pipe(socket);
      socket.pipe(proxySocket);

      proxySocket.on("error", () => socket.destroy());
      socket.on("error", () => proxySocket.destroy());
    });

    proxyReq.on("error", (err) => {
      console.error("[ws-proxy] WebSocket proxy error:", err.message);
      socket.destroy();
    });

    proxyReq.end();
  });

  return httpServer;
}
