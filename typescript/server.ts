#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import express from "express";
import { z } from "zod";
import dotenv from "dotenv";
import { SplunkClient, SplunkAPIError } from "./splunkClient";
import { formatEventsAsMarkdown, formatEventsAsCSV, formatEventsAsSummary } from "./helpers";
import { validateSplQuery, sanitizeOutput } from "./guardrails";

dotenv.config();

const config = {
  name: process.env.SERVER_NAME || "Splunk MCP",
  description: process.env.SERVER_DESCRIPTION || "MCP server for retrieving data from Splunk",
  host: process.env.HOST || "0.0.0.0",
  port: parseInt(process.env.PORT || "8050", 10),
  transport: process.env.TRANSPORT || "sse",
  log_level: process.env.LOG_LEVEL || "INFO",
  splunk_host: process.env.SPLUNK_HOST,
  splunk_port: parseInt(process.env.SPLUNK_PORT || "8089", 10),
  splunk_username: process.env.SPLUNK_USERNAME,
  splunk_password: process.env.SPLUNK_PASSWORD,
  splunk_token: process.env.SPLUNK_TOKEN,
  verify_ssl: process.env.VERIFY_SSL?.toLowerCase() === "true",
  spl_max_events_count: parseInt(process.env.SPL_MAX_EVENTS_COUNT || process.env.MAX_EVENTS_COUNT || "100000", 10),
  spl_risk_tolerance: parseInt(process.env.SPL_RISK_TOLERANCE || "75", 10),
  spl_safe_timerange: process.env.SPL_SAFE_TIMERANGE || "24h",
  spl_sanitize_output: process.env.SPL_SANITIZE_OUTPUT?.toLowerCase() === "true",
};

// Global Splunk client instance
let splunkClient: SplunkClient | null = null;

// Initialize Splunk client
async function initializeSplunkClient() {
  splunkClient = new SplunkClient(config);
  await splunkClient.connect();
  console.log("Splunk client connected");
}

// Factory: creates and configures a new McpServer instance.
//
// McpServer.connect() disconnects from any previously connected transport before
// connecting to the new one — it only supports one active transport at a time.
// Reusing a single shared instance across multiple SSE sessions therefore
// invalidates each session on the next connect(), causing tool-call POSTs to
// arrive for a transport whose internal response object has already been cleared,
// producing "SSE connection not established" errors and permanently hung requests.
//
// Solution: call createMcpServer() once per SSE connection so every session gets
// its own isolated server instance. The stdio path is unchanged (single
// connection, no concurrent sessions).
function createMcpServer(): McpServer {
  const server = new McpServer(
    {
      name: config.name,
      version: "0.1.0",
    },
    {
      capabilities: {
        tools: {},
        resources: {},
      },
    }
  );

  // Validate SPL tool
  server.tool(
    "validate_spl",
    "Validate an SPL query for potential risks and inefficiencies",
    {
      query: z.string().describe("The SPL query to validate"),
    },
    async ({ query }) => {
      const safeTimerange = config.spl_safe_timerange;
      const riskTolerance = config.spl_risk_tolerance;
      
      const [riskScore, riskMessage] = validateSplQuery(query, safeTimerange);
      
      const result = {
        risk_score: riskScore,
        risk_message: riskMessage,
        risk_tolerance: riskTolerance,
        would_execute: riskScore <= riskTolerance,
        execution_note: `Query would be ${riskScore <= riskTolerance ? 'executed' : 'BLOCKED - no search would be executed and no data would be returned'}`
      };
      
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    }
  );

  // Search oneshot tool
  server.tool(
    "search_oneshot",
    "Run a oneshot search query in Splunk and return results",
    {
      query: z.string().describe("The Splunk search query (e.g., 'index=main | head 10')"),
      earliest_time: z.string().default("-24h").describe("Start time for search (default: -24h)"),
      latest_time: z.string().default("now").describe("End time for search (default: now)"),
      max_count: z.number().default(100).describe("Maximum number of results to return (default: 100, or SPL_MAX_EVENTS_COUNT from .env, 0 = unlimited)"),
      output_format: z.string().default("json").describe("Format for results - json, markdown/md, csv, or summary (default: json)"),
      risk_tolerance: z.number().optional().describe("Override risk tolerance level (default: SPL_RISK_TOLERANCE from .env)"),
      sanitize_output: z.boolean().optional().describe("Override output sanitization (default: SPL_SANITIZE_OUTPUT from .env)"),
    },
    async ({ query, earliest_time, latest_time, max_count, output_format, risk_tolerance, sanitize_output }) => {
      if (!splunkClient) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: "Splunk client not initialized" }),
            },
          ],
        };
      }

      try {
        // Get risk tolerance and sanitization settings
        if (risk_tolerance === undefined) {
          risk_tolerance = config.spl_risk_tolerance;
        }
        if (sanitize_output === undefined) {
          sanitize_output = config.spl_sanitize_output;
        }
        
        // Validate query if risk_tolerance < 100
        if (risk_tolerance < 100) {
          const safeTimerange = config.spl_safe_timerange;
          const [riskScore, riskMessage] = validateSplQuery(query, safeTimerange);
          
          if (riskScore > risk_tolerance) {
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify({
                    error: `Query exceeds risk tolerance (${riskScore} > ${risk_tolerance}). No search was executed and no data was returned.`,
                    risk_score: riskScore,
                    risk_tolerance: risk_tolerance,
                    risk_message: riskMessage,
                    search_executed: false,
                    data_returned: null
                  }, null, 2)
                }
              ]
            };
          }
        }
        
        // Use configured max_events_count if max_count is default (100)
        if (max_count === 100) {
          max_count = config.spl_max_events_count;
        }

        // Execute search using client
        let events = await splunkClient.searchOneshot(query, earliest_time, latest_time, max_count);
        
        // Sanitize output if requested
        if (sanitize_output) {
          events = sanitizeOutput(events);
        }

        // Format results based on output_format
        let result: any;
        
        // Handle synonyms
        if (output_format === "md") {
          output_format = "markdown";
        }

        if (output_format === "json") {
          result = {
            query,
            event_count: events.length,
            events,
            search_params: {
              earliest_time,
              latest_time,
              max_count,
            },
          };
        } else if (output_format === "markdown") {
          result = {
            query,
            event_count: events.length,
            format: "markdown",
            content: formatEventsAsMarkdown(events, query),
            search_params: {
              earliest_time,
              latest_time,
              max_count,
            },
          };
        } else if (output_format === "csv") {
          result = {
            query,
            event_count: events.length,
            format: "csv",
            content: formatEventsAsCSV(events, query),
            search_params: {
              earliest_time,
              latest_time,
              max_count,
            },
          };
        } else if (output_format === "summary") {
          result = {
            query,
            event_count: events.length,
            format: "summary",
            content: formatEventsAsSummary(events, query, events.length),
            search_params: {
              earliest_time,
              latest_time,
              max_count,
            },
          };
        } else {
          result = { error: `Invalid output_format: ${output_format}. Must be one of: json, markdown (or md), csv, summary` };
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (error) {
        if (error instanceof SplunkAPIError) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({ error: error.message, details: error.details }),
              },
            ],
          };
        }
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: `Search failed: ${error}` }),
            },
          ],
        };
      }
    }
  );

  // Search export tool
  server.tool(
    "search_export",
    "Run an export search query in Splunk that streams results immediately",
    {
      query: z.string().describe("The Splunk search query"),
      earliest_time: z.string().default("-24h").describe("Start time for search (default: -24h)"),
      latest_time: z.string().default("now").describe("End time for search (default: now)"),
      max_count: z.number().default(100).describe("Maximum number of results to return (default: 100, or SPL_MAX_EVENTS_COUNT from .env, 0 = unlimited)"),
      output_format: z.string().default("json").describe("Format for results - json, markdown/md, csv, or summary (default: json)"),
      risk_tolerance: z.number().optional().describe("Override risk tolerance level (default: SPL_RISK_TOLERANCE from .env)"),
      sanitize_output: z.boolean().optional().describe("Override output sanitization (default: SPL_SANITIZE_OUTPUT from .env)"),
    },
    async ({ query, earliest_time, latest_time, max_count, output_format, risk_tolerance, sanitize_output }) => {
      if (!splunkClient) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: "Splunk client not initialized" }),
            },
          ],
        };
      }

      try {
        // Get risk tolerance and sanitization settings
        if (risk_tolerance === undefined) {
          risk_tolerance = config.spl_risk_tolerance;
        }
        if (sanitize_output === undefined) {
          sanitize_output = config.spl_sanitize_output;
        }
        
        // Validate query if risk_tolerance < 100
        if (risk_tolerance < 100) {
          const safeTimerange = config.spl_safe_timerange;
          const [riskScore, riskMessage] = validateSplQuery(query, safeTimerange);
          
          if (riskScore > risk_tolerance) {
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify({
                    error: `Query exceeds risk tolerance (${riskScore} > ${risk_tolerance}). No search was executed and no data was returned.`,
                    risk_score: riskScore,
                    risk_tolerance: risk_tolerance,
                    risk_message: riskMessage,
                    search_executed: false,
                    data_returned: null
                  }, null, 2)
                }
              ]
            };
          }
        }
        
        // Use configured max_events_count if max_count is default (100)
        if (max_count === 100) {
          max_count = config.spl_max_events_count;
        }

        // Execute export search using client
        let events = await splunkClient.searchExport(query, earliest_time, latest_time, max_count);
        
        // Sanitize output if requested
        if (sanitize_output) {
          events = sanitizeOutput(events);
        }

        // Format results based on output_format
        let result: any;
        
        // Handle synonyms
        if (output_format === "md") {
          output_format = "markdown";
        }

        if (output_format === "json") {
          result = {
            query,
            event_count: events.length,
            events,
            is_preview: false,
          };
        } else if (output_format === "markdown") {
          result = {
            query,
            event_count: events.length,
            format: "markdown",
            content: formatEventsAsMarkdown(events, query),
            is_preview: false,
          };
        } else if (output_format === "csv") {
          result = {
            query,
            event_count: events.length,
            format: "csv",
            content: formatEventsAsCSV(events, query),
            is_preview: false,
          };
        } else if (output_format === "summary") {
          result = {
            query,
            event_count: events.length,
            format: "summary",
            content: formatEventsAsSummary(events, query, events.length),
            is_preview: false,
          };
        } else {
          result = { error: `Invalid output_format: ${output_format}. Must be one of: json, markdown (or md), csv, summary` };
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (error) {
        if (error instanceof SplunkAPIError) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({ error: error.message, details: error.details }),
              },
            ],
          };
        }
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: `Export search failed: ${error}` }),
            },
          ],
        };
      }
    }
  );

  // Get indexes tool
  server.tool(
    "get_indexes",
    "Get list of available Splunk indexes with detailed information",
    {},
    async () => {
      if (!splunkClient) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: "Splunk client not initialized" }),
            },
          ],
        };
      }

      try {
        const indexes = await splunkClient.getIndexes();
        
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ indexes, count: indexes.length }, null, 2),
            },
          ],
        };
      } catch (error) {
        if (error instanceof SplunkAPIError) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({ error: error.message, details: error.details }),
              },
            ],
          };
        }
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: `Failed to get indexes: ${error}` }),
            },
          ],
        };
      }
    }
  );

  // Get saved searches tool
  server.tool(
    "get_saved_searches",
    "Get list of saved searches available in Splunk",
    {},
    async () => {
      if (!splunkClient) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: "Splunk client not initialized" }),
            },
          ],
        };
      }

      try {
        const savedSearches = await splunkClient.getSavedSearches();
        
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ saved_searches: savedSearches, count: savedSearches.length }, null, 2),
            },
          ],
        };
      } catch (error) {
        if (error instanceof SplunkAPIError) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({ error: error.message, details: error.details }),
              },
            ],
          };
        }
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: `Failed to get saved searches: ${error}` }),
            },
          ],
        };
      }
    }
  );

  // Run saved search tool
  server.tool(
    "run_saved_search",
    "Run a saved search by name",
    {
      search_name: z.string().describe("Name of the saved search to run"),
      trigger_actions: z.boolean().default(false).describe("Whether to trigger the search's actions (default: false)"),
    },
    async ({ search_name, trigger_actions }) => {
      if (!splunkClient) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: "Splunk client not initialized" }),
            },
          ],
        };
      }

      try {
        const result = await splunkClient.runSavedSearch(search_name, trigger_actions);
        
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (error) {
        if (error instanceof SplunkAPIError) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({ error: error.message, details: error.details }),
              },
            ],
          };
        }
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: `Failed to run saved search: ${error}` }),
            },
          ],
        };
      }
    }
  );

  // Get config tool
  server.tool(
    "get_config",
    "Get current server configuration",
    {},
    async () => {
      const configCopy = { ...config };
      // Remove sensitive information
      delete (configCopy as any).splunk_password;
      delete (configCopy as any).splunk_token;
      (configCopy as any).splunk_connected = splunkClient !== null;
      
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(configCopy, null, 2),
          },
        ],
      };
    }
  );

  // Resources
  server.resource(
    "saved-searches",
    "splunk://saved-searches",
    async () => {
      try {
        // Create temporary client for resource access
        const tempClient = new SplunkClient(config);
        await tempClient.connect();
        
        const savedSearches = await tempClient.getSavedSearches();
        await tempClient.disconnect();
        
        let content = "# Splunk Saved Searches\n\n";
        
        for (const search of savedSearches) {
          content += `## ${search.name}\n\n`;
          if (search.description) {
            content += `**Description:** ${search.description}\n`;
          }
          content += `**Query:** \`${search.search}\`\n`;
          if (search.is_scheduled) {
            content += `**Schedule:** ${search.cron_schedule || 'N/A'}\n`;
            if (search.next_scheduled_time) {
              content += `**Next Run:** ${search.next_scheduled_time}\n`;
            }
          }
          if (search.actions) {
            content += `**Actions:** ${search.actions}\n`;
          }
          content += "\n";
        }
        
        return {
          contents: [{
            uri: "splunk://saved-searches",
            text: content,
            mimeType: "text/plain",
          }],
        };
      } catch (error) {
        return {
          contents: [{
            uri: "splunk://saved-searches",
            text: `Error retrieving saved searches: ${error}`,
            mimeType: "text/plain",
          }],
        };
      }
    }
  );

  server.resource(
    "indexes",
    "splunk://indexes",
    async () => {
      try {
        // Create temporary client for resource access
        const tempClient = new SplunkClient(config);
        await tempClient.connect();
        
        const indexes = await tempClient.getIndexes();
        await tempClient.disconnect();
        
        let content = "# Splunk Indexes\n\n";
        content += "| Index | Type | Events | Size (MB) | Max Size | Time Range | Status |\n";
        content += "|-------|------|--------|-----------|----------|------------|--------|\n";
        
        for (const idx of indexes) {
          let timeRange = "N/A";
          if (idx.minTime && idx.maxTime) {
            timeRange = `${idx.minTime} to ${idx.maxTime}`;
          }
          
          const status = !idx.disabled ? "✓ Enabled" : "✗ Disabled";
          const maxSize = idx.maxDataSize || 'auto';
          
          content += `| ${idx.name} | ${idx.datatype || 'event'} | `;
          content += `${idx.totalEventCount.toLocaleString()} | `;
          content += `${idx.currentDBSizeMB.toFixed(2)} | `;
          content += `${maxSize} | ${timeRange} | ${status} |\n`;
        }
        
        content += "\n## Index Details\n\n";
        
        for (const idx of indexes) {
          if (idx.totalEventCount > 0) {  // Only show non-empty indexes
            content += `### ${idx.name}\n`;
            content += `- **Total Events:** ${idx.totalEventCount.toLocaleString()}\n`;
            content += `- **Current Size:** ${idx.currentDBSizeMB.toFixed(2)} MB\n`;
            content += `- **Max Size:** ${idx.maxDataSize || 'auto'}\n`;
            if (idx.frozenTimePeriodInSecs) {
              const frozenDays = parseInt(idx.frozenTimePeriodInSecs) / 86400;
              content += `- **Retention:** ${frozenDays.toFixed(0)} days\n`;
            }
            content += "\n";
          }
        }
        
        return {
          contents: [{
            uri: "splunk://indexes",
            text: content,
            mimeType: "text/plain",
          }],
        };
      } catch (error) {
        return {
          contents: [{
            uri: "splunk://indexes", 
            text: `Error retrieving indexes: ${error}`,
            mimeType: "text/plain",
          }],
        };
      }
    }
  );

  return server;
}

// Signal handler
function signalHandler() {
  console.log("\n\n✨ Server shutdown ...");
  process.exit(0);
}

async function main() {
  // Disable all console output for stdio transport to avoid warnings
  if (config.transport === "stdio") {
    const noop = () => {};
    console.log = noop;
    console.info = noop;
    console.warn = noop;
    console.error = noop;
  }
  
  console.log(`Starting ${config.name} server...`);
  console.log(`Transport: ${config.transport}`);
  
  // Initialize Splunk client
  try {
    await initializeSplunkClient();
  } catch (error) {
    console.error("Failed to initialize Splunk client:", error);
    process.exit(1);
  }
  
  // Set up signal handlers
  process.on('SIGINT', signalHandler);
  process.on('SIGTERM', signalHandler);
  
  if (config.transport === "stdio") {
    const server = createMcpServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.log("Server running on stdio");
  } else if (config.transport === "sse") {
    const app = express();
    app.use(express.json());
    
    const transports: { [sessionId: string]: SSEServerTransport } = {};
    
    // SSE endpoint handler
    const sseHandler: express.RequestHandler = async (req, res) => {
      console.log(`Received ${req.method} request to /sse`);
      
      // For HEAD requests, just return the headers without establishing a connection
      if (req.method === 'HEAD') {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.end();
        return;
      }
      
      // For GET requests, establish SSE connection.
      // A new McpServer instance is created for each connection: McpServer.connect()
      // disconnects from any prior transport before connecting to the new one, so a
      // single shared instance would invalidate all other active sessions on each
      // new client connect.
      const transport = new SSEServerTransport("/messages", res);
      const sessionId = transport.sessionId;
      transports[sessionId] = transport;
      
      transport.onclose = () => {
        console.log(`SSE transport closed for session ${sessionId}`);
        delete transports[sessionId];
      };
      
      const sessionServer = createMcpServer();
      await sessionServer.connect(transport);
      console.log(`SSE transport connected for session ${sessionId}`);
    };
    
    // Handle both GET and HEAD requests to /sse
    app.get("/sse", sseHandler);
    app.head("/sse", sseHandler);
    
    // Messages endpoint - handle both query param and header for session ID
    app.post("/messages", async (req, res) => {
      console.log("Received POST request to /messages");
      
      // Try to get session ID from query param first (SDK behavior), then header
      const sessionId = req.query.sessionId as string || req.get("x-session-id");
      if (!sessionId) {
        res.status(400).json({ error: "Missing sessionId parameter or x-session-id header" });
        return;
      }
      
      const transport = transports[sessionId];
      if (!transport) {
        res.status(404).json({ error: "Session not found" });
        return;
      }
      
      try {
        await transport.handlePostMessage(req, res, req.body);
      } catch (error) {
        console.error("Error handling message:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });
    
    app.listen(config.port, config.host, () => {
      console.log(`SSE Server running on http://${config.host}:${config.port}/sse`);
    });
  } else {
    throw new Error(`Unknown transport: ${config.transport}`);
  }
}

main().catch((error) => {
  console.error("Server error:", error);
  process.exit(1);
});
