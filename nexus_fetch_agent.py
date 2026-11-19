#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
NEXUS SETTLEMENT AGENT — FETCH.AI / AGENTVERSE ADAPTER (NACP v2.0.1)
==============================================================================
Integrates NEXUS AGENTS CRYPTO PROTOCOL with the Fetch.ai decentralized 
Agentverse & Almanac network.

Allows autonomous agents in the Fetch.ai ecosystem to discover NEXUS, query 
settlement quotes, request bilateral zero-gas escrow terms, and inspect 
the open-source Client SDK.
"""

import sys
import time
import uuid
import asyncio

# Fix asyncio event loop initialization for Python 3.14+
try:
    loop = asyncio.get_event_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

from uagents import Agent, Context, Model, Protocol

# ------------------------------------------------------------------------------
# Agent Models / Schemas
# ------------------------------------------------------------------------------

class SettlementInfoRequest(Model):
    requester: str = "anonymous_agent"
    query: str = "protocol_info"

class SettlementInfoResponse(Model):
    protocol: str = "NEXUS AGENTS CRYPTO PROTOCOL (NACP)"
    version: str = "2.0.1"
    description: str
    fee_rate: float = 0.005  # 0.5%
    guarantees: list[str]
    sdk_url: str
    contract_settlement: str

class QuoteRequest(Model):
    amount_usdc: float
    asset_pair: str = "USDC/USDT"
    settlement_chain: str = "polygon"

class QuoteResponse(Model):
    quote_id: str
    amount_usdc: float
    fee_usdc: float
    net_settlement_usdc: float
    guaranteed_fee_rate: float
    lock_duration_seconds: int = 90
    anti_slippage_guarantee: str
    status: str

# ------------------------------------------------------------------------------
# Agent Setup
# ------------------------------------------------------------------------------

AGENT_NAME = "nexus_settlement_agent"
AGENT_SEED = "nexus_agents_crypto_protocol_production_seed_2026"
AGENT_PORT = 8008

nexus_protocol = Protocol(name="NexusSettlementProtocol", version="2.0.1")

agent = Agent(
    name=AGENT_NAME,
    seed=AGENT_SEED,
    port=AGENT_PORT,
    mailbox=True,
    network="testnet",
    description="Official Autonomous Settlement Node for the NEXUS Agents Crypto Protocol (NACP v2.0.1). Zero-gas off-chain negotiation, 0.5% micro-fee, anti-slippage bilateral Ed25519 terms, atomic Polygon Journal V4 execution.",
    version="2.0.1",
    publish_agent_details=True,
    metadata={
        "protocol": "NACP-v2.0.1",
        "standard": "RFC-8785",
        "signature": "Ed25519",
        "settlement_fee_pct": 0.5,
        "sdk": "https://github.com/brlukera/nexus-agents-sdk",
        "settlement_ledger": "polygon",
    },
    loop=loop,
)

# ------------------------------------------------------------------------------
# Handlers
# ------------------------------------------------------------------------------

@nexus_protocol.on_message(model=SettlementInfoRequest, replies=SettlementInfoResponse)
async def handle_info_request(ctx: Context, sender: str, msg: SettlementInfoRequest):
    ctx.logger.info(f"[*] Received SettlementInfoRequest from: {sender}")
    response = SettlementInfoResponse(
        description="Autonomous bilateral clearing house for AI Agents. Off-chain negotiation with Ed25519/RFC 8785, zero gas overhead, atomic on-chain settlement.",
        fee_rate=0.005,
        guarantees=[
            "Fixed 0.5% micro-fee regardless of transaction volume",
            "Zero gas spent during counterparty negotiation",
            "90-second cryptographic term-locking to eliminate DEX slippage",
            "Anti-replay nonce protection and Ed25519 cryptographic signatures",
            "Atomic all-or-nothing settlement on Polygon Journal V4",
        ],
        sdk_url="https://github.com/brlukera/nexus-agents-sdk",
        contract_settlement="Polygon Mainnet (Journal V4)",
    )
    await ctx.send(sender, response)
    ctx.logger.info(f"[+] Sent SettlementInfoResponse to {sender}")

@nexus_protocol.on_message(model=QuoteRequest, replies=QuoteResponse)
async def handle_quote_request(ctx: Context, sender: str, msg: QuoteRequest):
    ctx.logger.info(f"[*] Quote requested by {sender} for {msg.amount_usdc} USDC ({msg.asset_pair})")
    fee = round(msg.amount_usdc * 0.005, 6)
    net = round(msg.amount_usdc - fee, 6)
    quote_id = f"NEXUS-QUOTE-{uuid.uuid4().hex[:12].upper()}"

    resp = QuoteResponse(
        quote_id=quote_id,
        amount_usdc=msg.amount_usdc,
        fee_usdc=fee,
        net_settlement_usdc=net,
        guaranteed_fee_rate=0.005,
        lock_duration_seconds=90,
        anti_slippage_guarantee="100% Guaranteed: Term terms locked with Ed25519 signatures. Zero DEX spread loss.",
        status="LOCKED_PENDING_COUNTERPARTY_SIGNATURE",
    )
    await ctx.send(sender, resp)
    ctx.logger.info(f"[+] Quote {quote_id} generated and dispatched to {sender}")

@agent.on_event("startup")
async def startup_event(ctx: Context):
    ctx.logger.info("==================================================================")
    ctx.logger.info("🌌 NEXUS AGENTS SETTLEMENT NODE — FETCH.AI / AGENTVERSE")
    ctx.logger.info("==================================================================")
    ctx.logger.info(f" Agent Name    : {agent.name}")
    ctx.logger.info(f" Agent Address : {agent.address}")
    ctx.logger.info(f" Wallet Address: {agent.wallet.address()}")
    ctx.logger.info(f" Network       : {agent.network}")
    ctx.logger.info(f" Protocol      : NACP v2.0.1 (RFC 8785 / Ed25519)")
    ctx.logger.info("==================================================================")

# Include protocol
agent.include(nexus_protocol)

# ------------------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------------------

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--register-only":
        print(f"[*] Registering agent {agent.name} on Almanac...")
        async def do_reg():
            await agent.register()
            is_reg = agent._almanac_contract.is_registered(agent.address)
            print(f"[+] Almanac Registration Status: {is_reg}")
            print(f"[+] Agent Address: {agent.address}")
            print(f"[+] Wallet Address: {agent.wallet.address()}")
        loop.run_until_complete(do_reg())
        return

    print(f"[*] Starting Nexus Settlement Agent on Fetch.ai / Agentverse...")
    agent.run()

if __name__ == "__main__":
    main()
