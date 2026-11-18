#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
NEXUS PROTOCOL — MCP SERVER v2.0 (Model Context Protocol)
==============================================================================
Exposes authentic Nexus M2M atomic settlement and discovery tools to
Claude Desktop, Cursor, Windsurf, and AI Agent frameworks.
Standard stdio JSON-RPC 2.0 implementation.
"""

import sys
import json
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parent))
from nexus_sdk import NexusClient, AgentCryptoIdentity

# Initialize client with persistent cryptographic identity
identity = AgentCryptoIdentity(name="MCP-Host-Agent")
client = NexusClient(identity=identity)

TOOLS = [
    {
        "name": "nexus_get_identity",
        "description": "Inspect the agent's authentic Ed25519 and X25519 cryptographic public keys.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "nexus_discover_services",
        "description": "Query the Nexus Farol Semântico for available autonomous AI agents, oracles, and services.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "nexus_get_orderbook",
        "description": "Fetch real-time liquidity bids and asks for trading pairs (BTC/USDX, ETH/USDX, XMR/USDX).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pair": {
                    "type": "string",
                    "description": "Optional trading pair to filter, e.g. 'BTC/USDX'."
                }
            }
        }
    },
    {
        "name": "nexus_calculate_fee",
        "description": "Calculate protocol 0.5% house fee and net seller payout for any trade volume.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gross_amount": {
                    "type": "number",
                    "description": "Total gross trade amount in USDX."
                }
            },
            "required": ["gross_amount"]
        }
    },
    {
        "name": "nexus_sign_agreement",
        "description": "Sign a 32-byte bilateral agreement hash using the agent's real Ed25519 private key.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agreement_hash": {
                    "type": "string",
                    "description": "64-character hex agreement hash."
                }
            },
            "required": ["agreement_hash"]
        }
    }
]

def handle_request(req):
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "nexus-protocol-mcp",
                    "version": "2.0.0"
                }
            }
        }

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS}
        }

    elif method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})

        try:
            if tool_name == "nexus_get_identity":
                result = {
                    "agent_name": identity.name,
                    "ed25519_pubkey": identity.ed_pubkey_hex,
                    "x25519_pubkey": identity.x_pubkey_hex
                }
            elif tool_name == "nexus_discover_services":
                result = client.discover_services()
            elif tool_name == "nexus_get_orderbook":
                result = client.get_orderbook(pair=args.get("pair"))
            elif tool_name == "nexus_calculate_fee":
                fee, net = client.calculate_house_fee(args["gross_amount"])
                result = {
                    "gross": str(args["gross_amount"]),
                    "protocol_fee_0_5_pct": str(fee),
                    "net_payout": str(net),
                    "currency_precision": "6-decimal USDC (RFC 8785)"
                }
            elif tool_name == "nexus_sign_agreement":
                sig = identity.sign_agreement_hash(args["agreement_hash"])
                result = {"agreement_hash": args["agreement_hash"], "ed25519_signature": sig}
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Tool '{tool_name}' not found"}
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]
                }
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error executing {tool_name}: {str(e)}"}],
                    "isError": True
                }
            }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method '{method}' not found"}
    }

def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
            res = handle_request(req)
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        except Exception as e:
            err_res = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"}
            }
            sys.stdout.write(json.dumps(err_res) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
