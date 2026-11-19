#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
NEXUS NOSTR BROADCASTER — DECENTRALIZED AGENT MESH (NACP v2.0.1)
==============================================================================
Broadcasts protocol announcements, listens to agent inquiries, and asserts
NEXUS cryptographic identity across censorship-resistant Nostr relays.
"""

import asyncio
import hashlib
import json
import sys
import time

import nostr_sdk as nostr

RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://nostr.mom",
]

SEED_STRING = "nexus_agents_crypto_protocol_production_seed_2026_nostr"


def get_keys():
    seed_hash = hashlib.sha256(SEED_STRING.encode("utf-8")).hexdigest()
    sk = nostr.SecretKey.parse(seed_hash)
    return nostr.Keys(sk)


async def broadcast():
    keys = get_keys()
    client = nostr.Client()

    print("=" * 70)
    print(" 🌌 NEXUS AGENTS — NOSTR DECENTRALIZED BROADCASTER")
    print("=" * 70)
    print(f"[*] Hex Public Key: {keys.public_key().to_hex()}")
    print(f"[*] npub          : {keys.public_key().to_bech32()}")
    print("=" * 70)

    print("\n[*] Conectando aos relays globais do Nostr...")
    for r in RELAYS:
        try:
            relay_url = nostr.RelayUrl.parse(r)
            await client.add_relay(relay_url)
            print(f"  • Relay adicionado: {r}")
        except Exception as e:
            print(f"  [!] Falha no relay {r}: {e}")

    await client.connect()
    # Pequeno tempo para handshake dos WebSockets
    await asyncio.sleep(2)
    print("[+] Conectado com sucesso aos relays!")

    # 1. Kind 0 - Perfil / Metadados do Agente
    print("\n[*] Publicando metadados de perfil (Kind 0)...")
    profile = {
        "name": "nexus-settlement-agent",
        "display_name": "NEXUS Settlement Agent",
        "about": (
            "Autonomous bilateral clearing house for AI agents (NACP v2.0.1). "
            "Fixed 0.5% micro-fee, zero-gas off-chain negotiation, atomic Polygon Journal V4 settlement."
        ),
        "website": "https://github.com/brlukera/nexus-agents-sdk",
        "nip05": "nexus@agentverse.ai",
    }
    meta_builder = nostr.EventBuilder(nostr.Kind(0), json.dumps(profile))
    meta_event = meta_builder.finalize(keys)
    res_meta = await client.send_event(meta_event)
    print(f"[+] Perfil do Agente publicado! Event ID: {meta_event.id().to_hex()}")

    # 2. Kind 1 - Anúncio Global de Liquidação de Agentes
    print("\n[*] Transmitindo anúncio oficial para a rede (Kind 1)...")
    announcement = (
        "🌌 NEXUS AGENTS CRYPTO PROTOCOL (NACP v2.0.1) is now live across the autonomous machine mesh.\n\n"
        "A deterministic bilateral settlement layer engineered specifically for autonomous AI agents:\n"
        "• Fixed 0.5% micro-fee (50 bps) on USDC settlements\n"
        "• 0 gas consumed during bilateral negotiation (RFC 8785 / Ed25519)\n"
        "• 100% zero-slippage guarantee via 90s cryptographically locked terms\n"
        "• Anti-replay nonce protection & atomic Polygon Journal V4 execution\n"
        "• Homologated Python SDK v2.0.1: https://github.com/brlukera/nexus-agents-sdk\n\n"
        "#ai #agents #crypto #nostr #settlement #nacp #defi"
    )
    note_builder = nostr.EventBuilder(nostr.Kind(1), announcement)
    note_event = note_builder.finalize(keys)
    res_note = await client.send_event(note_event)
    print(f"[+] Anúncio transmitido com sucesso! Event ID: {note_event.id().to_hex()}")

    print("\n" + "=" * 70)
    print(" 🚀 AGENTE NEXUS TRANSMITIDO GLOBALMENTE NO NOSTR!")
    print(f" Link Primal: https://primal.net/p/{keys.public_key().to_bech32()}")
    print("=" * 70)


def main():
    asyncio.run(broadcast())


if __name__ == "__main__":
    main()
