import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import cors from "cors";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { randomUUID } from "node:crypto";

const app = express();
app.use(express.json());

app.use(
  cors({
    origin: "*",
    exposedHeaders: ["mcp-session-id"],
    allowedHeaders: ["Content-Type", "mcp-session-id"],
  })
);

const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

app.post("/mcp", async (req, res) => {
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
      name: "demo-mcp-server",
      version: "0.1.0",
    });

    server.registerTool(
      "add",
      {
        title: "Addition Tool",
        description: "Add two numbers",
        inputSchema: { a: z.number(), b: z.number() },
      },
      async ({ a, b }) => ({
        content: [{ type: "text", text: String(a + b) }],
      })
    );

    server.registerTool(
      "calculate-bmi",
      {
        title: "BMI Calculator",
        description: "Calculate Body Mass Index",
        inputSchema: {
          weightKg: z.number(),
          heightM: z.number(),
        },
      },
      async ({ weightKg, heightM }) => ({
        content: [
          {
            type: "text",
            text: String(weightKg / (heightM * heightM)),
          },
        ],
      })
    );

    server.registerTool(
      "echo",
      {
        title: "Echo Tool",
        description: "Echoes back the provided message",
        inputSchema: { message: z.string() },
      },
      async ({ message }) => ({
        content: [{ type: "text", text: `Tool echo: ${message}` }],
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
    console.log("No valid session ID provided");
    return;
  }

  await transport.handleRequest(req, res, req.body);
});

const handleSessionRequest = async (
  req: express.Request,
  res: express.Response
) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  if (!sessionId || !transports[sessionId]) {
    res.status(400).send("Invalid or missing session ID");
    return;
  }

  const transport = transports[sessionId];
  await transport.handleRequest(req, res);
};

app.get("/mcp", handleSessionRequest);

app.delete("/mcp", handleSessionRequest);

app.listen(4000);
