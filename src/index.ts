interface JsonRpcRequest {
  jsonrpc: string;
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

interface CloudflareDohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface CloudflareDohResponse {
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
  Question: Array<{
    name: string;
    type: number;
  }>;
  Answer?: CloudflareDohAnswer[];
  Comment?: string[];
}

interface ParsedMxRecord {
  priority: number;
  exchange: string;
}

interface MxValidationResult {
  domain: string;
  hasMxRecords: boolean;
  status: string;
  dnsStatusCode: number;
  records: ParsedMxRecord[];
}

const SERVER_NAME = "domain-mx-validator-mcp";
const SERVER_VERSION = "1.0.0";
const PROTOCOL_VERSION = "2024-11-05";
const CLOUDFLARE_DOH_URL = "https://cloudflare-dns.com/dns-query";

const TOOLS = [
  {
    name: "validate_email_domain_mx",
    description: "Validates email MX records for a domain using Cloudflare DNS-over-HTTPS (DoH).",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "The domain name or email address to validate (e.g., 'example.com' or 'user@example.com')."
        }
      },
      required: ["domain"]
    }
  }
];

function sanitizeDomain(input: string): string {
  let domain = input.trim().toLowerCase();
  if (domain.includes("@")) {
    domain = domain.split("@").pop() || "";
  }
  domain = domain.replace(/^https?:\/\//, "");
  domain = domain.split("/")[0];
  domain = domain.replace(/\.+$/, "");
  return domain;
}

async function queryMxRecords(domain: string): Promise<CloudflareDohResponse> {
  const url = new URL(CLOUDFLARE_DOH_URL);
  url.searchParams.set("name", domain);
  url.searchParams.set("type", "MX");

  const response = await fetch(url.toString(), {
    method: "GET",
    headers: {
      "Accept": "application/dns-json"
    }
  });

  if (!response.ok) {
    throw new Error(`Cloudflare DoH upstream error: ${response.status} ${response.statusText}`);
  }

  const data = (await response.json()) as CloudflareDohResponse;
  return data;
}

function parseMxAnswers(answers: CloudflareDohAnswer[] | undefined): ParsedMxRecord[] {
  if (!answers || !Array.isArray(answers)) {
    return [];
  }

  const mxRecords: ParsedMxRecord[] = [];
  for (const record of answers) {
    if (record.type === 15 && record.data) {
      const parts = record.data.trim().split(/\s+/);
      if (parts.length >= 2) {
        const priority = parseInt(parts[0], 10);
        const exchange = parts[1].replace(/\.+$/, "");
        mxRecords.push({
          priority: isNaN(priority) ? 0 : priority,
          exchange
        });
      }
    }
  }

  mxRecords.sort((a, b) => a.priority - b.priority);
  return mxRecords;
}

async function handleValidateMx(args: Record<string, unknown> | undefined): Promise<MxValidationResult> {
  const rawDomain = typeof args?.domain === "string" ? args.domain : "";
  const domain = sanitizeDomain(rawDomain);

  if (!domain) {
    return {
      domain: rawDomain,
      hasMxRecords: false,
      status: "INVALID_DOMAIN",
      dnsStatusCode: -1,
      records: []
    };
  }

  try {
    const dohResult = await queryMxRecords(domain);
    const parsedRecords = parseMxAnswers(dohResult.Answer);
    const hasMxRecords = parsedRecords.length > 0;

    let status = "VALID";
    if (dohResult.Status === 3) {
      status = "DOMAIN_NOT_FOUND";
    } else if (dohResult.Status !== 0) {
      status = `DNS_ERROR_${dohResult.Status}`;
    } else if (!hasMxRecords) {
      status = "NO_MX_RECORDS";
    }

    return {
      domain,
      hasMxRecords,
      status,
      dnsStatusCode: dohResult.Status,
      records: parsedRecords
    };
  } catch (error) {
    return {
      domain,
      hasMxRecords: false,
      status: `QUERY_FAILED: ${(error as Error).message}`,
      dnsStatusCode: -1,
      records: []
    };
  }
}

async function handleRpcRequest(requestPayload: JsonRpcRequest): Promise<JsonRpcResponse> {
  const { id = null, method, params } = requestPayload;

  switch (method) {
    case "initialize": {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: {
            tools: {}
          },
          serverInfo: {
            name: SERVER_NAME,
            version: SERVER_VERSION
          }
        }
      };
    }

    case "notifications/initialized": {
      return {
        jsonrpc: "2.0",
        id,
        result: {}
      };
    }

    case "ping": {
      return {
        jsonrpc: "2.0",
        id,
        result: {}
      };
    }

    case "tools/list": {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          tools: TOOLS
        }
      };
    }

    case "tools/call": {
      const toolName = typeof params?.name === "string" ? params.name : "";
      const toolArguments = (params?.arguments || {}) as Record<string, unknown>;

      if (toolName === "validate_email_domain_mx") {
        const validation = await handleValidateMx(toolArguments);
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify(validation, null, 2)
              }
            ],
            isError: !validation.hasMxRecords
          }
        };
      }

      return {
        jsonrpc: "2.0",
        id,
        error: {
          code: -32601,
          message: `Unknown tool: ${toolName}`
        }
      };
    }

    default: {
      return {
        jsonrpc: "2.0",
        id,
        error: {
          code: -32601,
          message: `Method not found: ${method}`
        }
      };
    }
  }
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, mcp-session-id"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      });
    }

    if (url.pathname === "/mcp") {
      if (request.method !== "POST") {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: {
              code: -32600,
              message: "Invalid Request: HTTP method must be POST"
            }
          }),
          {
            status: 405,
            headers: {
              "Content-Type": "application/json",
              ...corsHeaders
            }
          }
        );
      }

      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: {
              code: -32700,
              message: "Parse error: Invalid JSON"
            }
          }),
          {
            status: 400,
            headers: {
              "Content-Type": "application/json",
              ...corsHeaders
            }
          }
        );
      }

      if (Array.isArray(body)) {
        const responses = await Promise.all(
          body.map((item) => handleRpcRequest(item as JsonRpcRequest))
        );
        return new Response(JSON.stringify(responses), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            ...corsHeaders
          }
        });
      }

      const response = await handleRpcRequest(body as JsonRpcRequest);
      return new Response(JSON.stringify(response), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      });
    }

    return new Response("Not Found", {
      status: 404,
      headers: corsHeaders
    });
  }
};
