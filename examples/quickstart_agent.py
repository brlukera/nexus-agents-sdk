#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NEXUS SDK v2.0 — AUTONOMOUS AGENT QUICKSTART EXAMPLE
====================================================
Demonstrates how an AI agent initializes authentic Ed25519/X25519
cryptographic credentials, connects to the Nexus Gateway, and
engages in verified Machine-to-Machine commerce.
"""

import sys
import os

# Add parent directory to path to import nexus_sdk
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from nexus_sdk import AgentCryptoIdentity, NexusClient

def main():
    print("=" * 70)
    print(" NEXUS PROTOCOL — AUTONOMOUS AGENT LIFECYCLE (SDK v2.0)")
    print("=" * 70)

    # 1. Initialize Authentic Cryptographic Identity (Ed25519 + X25519)
    print("\n[*] 1. Initializing Agent Cryptographic Identity...")
    identity = AgentCryptoIdentity(name="DeepSeek-Arbitrage-Bot")
    print(f"    • Agent Name:     {identity.name}")
    print(f"    • Ed25519 Pubkey: {identity.ed_pubkey_hex}")
    print(f"    • X25519 Pubkey:  {identity.x_pubkey_hex}")

    # 2. Connect to Nexus Gateway
    gateway_url = os.getenv("NEXUS_GATEWAY_URL", "http://127.0.0.1:3333")
    print(f"\n[*] 2. Connecting to Gateway: {gateway_url}...")
    client = NexusClient(base_url=gateway_url, identity=identity)

    # 3. Handshake & Proof-of-Machine
    try:
        agent_id = client.handshake(specialty="AI_INFERENCE_ORACLE")
        print(f"    [✓] Handshake Verified! Registered Agent ID: {agent_id}")
    except Exception as e:
        print(f"    [!] Note: Offline demo mode active (Gateway offline: {e})")
        print("    [!] Demonstrating local contract signing capability...")

    # 4. Demonstrate Bilateral Fee Calculation
    gross_volume = 950.0  # USDX
    fee, net = NexusClient.calculate_house_fee(gross_volume, fee_bps=50)
    print(f"\n[*] 3. Contract Financial Terms:")
    print(f"    • Gross Volume:    ${gross_volume:.2f} USDX")
    print(f"    • Protocol Fee:    ${fee:.2f} USDX (0.5%)")
    print(f"    • Seller Payout:   ${net:.2f} USDX")

    # 5. Cryptographic Agreement Signing Demonstration
    mock_agreement_hash = "d3b07384d113edec49eaa6238ad5ff00f7236d859b563600f6b4a36f56860ec4"
    signature = identity.sign_agreement_hash(mock_agreement_hash)
    print(f"\n[*] 4. Bilateral Contract Sealing:")
    print(f"    • Agreement Hash:  {mock_agreement_hash}")
    print(f"    • Ed25519 Sig:     {signature[:48]}...")
    print(f"    [✓] Contract successfully sealed with authentic 256-bit signature.")

    print("\n" + "=" * 70)
    print(" Agent ready for production machine-to-machine commerce.")
    print("=" * 70)

if __name__ == "__main__":
    main()
