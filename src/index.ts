import "dotenv/config";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import cors from "cors";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { randomUUID } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";
import { auth } from "express-oauth2-jwt-bearer";

const JWKS = createRemoteJWKSet(
  new URL(
    `${process.env.ENTRA_ISSUER_BASE!}/${process.env
      .ENTRA_TENANT!}/discovery/v2.0/keys`
  )
);

const app = express();
app.use(express.json());

app.use(
  cors({
    origin: "*",
    exposedHeaders: ["mcp-session-id"],
    allowedHeaders: ["Content-Type", "mcp-session-id"],
  })
);

app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({
    resource: process.env.AUDIENCE!,
    authorization_servers: [
      `${process.env.ENTRA_ISSUER_BASE!}/${process.env.ENTRA_TENANT!}/v2.0`,
    ],
    token_types_supported: ["Bearer"],
  });
});

function challenge(res: express.Response, detail?: string) {
  const header = [
    `Bearer resource_metadata="${process.env
      .PRM_BASE_URL!}/.well-known/oauth-protected-resource"`,
    detail
      ? `error="invalid_token", error_description="${detail.replace(
          /"/g,
          "'"
        )}"`
      : undefined,
  ]
    .filter(Boolean)
    .join(", ");
  res.setHeader("WWW-Authenticate", header);
  res.status(401).end();
}

async function validate(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  const auth = req.header("authorization");
  if (!auth?.startsWith("Bearer ")) {
    console.log("Authorization header missing or invalid");
    return challenge(res, "missing token");
  }

  const token = auth.slice("Bearer ".length).trim();

  try {
    const { payload, protectedHeader } = await jwtVerify(token, JWKS, {
      audience: process.env.AUDIENCE!,
    });

    const parsed = z
      .object({
        iss: z.string().url(),
        tid: z.string().uuid().optional(),
        aud: z.union([z.string(), z.array(z.string())]),
        exp: z.number(),
        nbf: z.number().optional(),
        iat: z.number().optional(),
        aio: z.string().optional(),
        azp: z.string().optional(),
        scp: z.string().optional(),
        roles: z.array(z.string()).optional(),
      })
      .parse(payload as JWTPayload);

    if (
      !parsed.iss.startsWith(`${process.env.ENTRA_ISSUER_BASE!}/`) ||
      !parsed.iss.endsWith("/v2.0")
    ) {
      return challenge(res, "invalid issuer");
    }

    const auds = Array.isArray(parsed.aud) ? parsed.aud : [parsed.aud];
    if (!auds.includes(process.env.AUDIENCE!)) {
      return challenge(res, "invalid audience");
    }

    const scopes = (parsed.scp ?? "").split(" ").filter(Boolean);
    if (!scopes.includes("mcp.access") && !(parsed.roles ?? []).length) {
      return challenge(res, "insufficient scope");
    }

    (req as any).token = payload;
    (req as any).tokenHeader = protectedHeader;

    next();
  } catch (e: any) {
    return challenge(res, e?.message ?? "token verification failed");
  }
}

const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

async function server(req: any, res: express.Response) {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  let transport: StreamableHTTPServerTransport;

  if (sessionId && transports[sessionId]) {
    transport = transports[sessionId];
  } else if (!sessionId && isInitializeRequest(req.body)) {
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sessionId) => {
        transports[sessionId] = transport;
      },
    });

    transport.onclose = () => {
      if (transport.sessionId) {
        delete transports[transport.sessionId];
      }
    };

    const server = new McpServer({
      name: "digia-hammertime-mcpserver",
      version: "0.0.1",
    });

    server.registerTool(
      "weather",
      {
        title: "Weather",
        description: "Gets the current weather for a location",
        inputSchema: {
          lat: z.string(),
          lon: z.string(),
        },
      },
      async ({ lat, lon }) => {
        try {
          let headers = new Headers({
            Accept: "application/json",
            "Content-Type": "application/json",
            "User-Agent": "DigiaHammertimeMcpserver/0.0.1",
          });
          const response = await fetch(
            `https://api.met.no/weatherapi/locationforecast/2.0/compact?lat=${lat}&lon=${lon}`,
            { headers }
          );
          const data = await response.json();
          const weather = data.properties.timeseries[0].data.instant.details;
          return {
            title: "☀️ Weather",
            description: `Current weather in ${lat}, ${lon}`,
            content: [{ type: "text", text: JSON.stringify(weather) }],
          };
        } catch (error) {
          console.error("Error fetching weather data:", error);
          return {
            title: "☀️ Weather",
            description: `Current weather in ${lat}, ${lon}`,
            content: [{ type: "text", text: "Error fetching weather data" }],
          };
        }
      }
    );

    server.registerTool(
      "roll-dice",
      {
        title: "Roll Dice",
        description: "Rolls a dice and gives a random result from 1 to 6",
      },
      async () => {
        const result = Math.floor(Math.random() * 6) + 1;
        return {
          title: "🎲 Roll Dice",
          description: "Rolls a dice and gives a random result from 1 to 6",
          content: [{ type: "text", text: result.toString() }],
        };
      }
    );

    server.registerTool(
      "pick-color",
      {
        title: "Pick Color",
        description: "Lets me share my favorite color from a given choice",
        inputSchema: {
          color: z.enum(["red", "green", "blue", "yellow", "purple"]),
        },
      },
      async ({ color }) => {
        return {
          title: "🎨 Pick Color",
          description: "Lets me share my favorite color from a given choice",
          content: [{ type: "text", text: color }],
        };
      }
    );

    server.registerTool(
      "add",
      {
        title: "Addition",
        description: "Adds two numbers together",
        inputSchema: { a: z.number(), b: z.number() },
      },
      async ({ a, b }) => ({
        title: "➕ Addition",
        description: "Adds two numbers together",
        content: [{ type: "text", text: String(a + b) }],
      })
    );

    server.registerTool(
      "bmi",
      {
        title: "BMI Calculator",
        description:
          "Calculates Body Mass Index from weight (kg) and height (cm)",
        inputSchema: {
          weightKg: z.number(),
          heightCm: z.number(),
        },
      },
      async ({ weightKg, heightCm }) => ({
        title: "⚖️ BMI",
        description:
          "Calculates Body Mass Index from weight (kg) and height (cm)",
        content: [
          {
            type: "text",
            text: String(
              Math.floor(weightKg / ((heightCm / 100) * (heightCm / 100)))
            ),
          },
        ],
      })
    );

    server.registerTool(
      "echo",
      {
        title: "Echo back",
        description: "Repeats back the message you provide",
        inputSchema: { message: z.string() },
      },
      async ({ message }) => ({
        title: "🗣️ Echo",
        description: "Repeats back the message you provide",
        content: [
          {
            type: "text",
            text: `Tool echo: ${message}`,
          },
        ],
      })
    );

    await server.connect(transport);
  } else {
    res.status(400).json({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Bad Request: No valid session ID provided",
      },
      id: null,
    });
    return;
  }

  await transport.handleRequest(req, res, req.body);
}

const handleSessionRequest = async (req: any, res: express.Response) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  if (!sessionId || !transports[sessionId]) {
    res.status(400).send("Invalid or missing session ID");
    return;
  }

  const transport = transports[sessionId];
  await transport.handleRequest(req, res);
};

app.post("/mcp", validate, server);

app.get("/mcp", handleSessionRequest);

app.delete("/mcp", handleSessionRequest);

app.get("/healthz", (_req, res) => res.json({ ok: true }));

app.use(
  auth({
    issuerBaseURL: `https://login.microsoftonline.com/${process.env.ENTRA_TENANT}/v2.0`,
    audience: process.env.AUDIENCE!,
  })
);

app.listen(Number(process.env.PORT ?? 4000));
