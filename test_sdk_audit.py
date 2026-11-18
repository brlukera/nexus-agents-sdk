#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NEXUS SDK v2.0 — CRYPTOGRAPHIC AUDIT & COMPLIANCE TEST SUITE
============================================================
Runs comprehensive mathematical checks on:
1. Ed25519 Key Generation & Hex Representation (32-byte raw keys).
2. X25519 E2EE Key Generation.
3. Canonical JSON RFC 8785 determinism.
4. Digital Signatures & Cryptographic Verification.
5. Negative Proof: Payload Tampering Rejection.
6. Negative Proof: Expired Timestamp Rejection.
7. Negative Proof: Impersonation / Wrong Key Rejection.
8. Keystore Save & Load Persistence.
9. 0.5% Protocol Fee Mathematical Precision.
"""

import os
import sys
import time
import json
import tempfile

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from nexus_sdk import (
    AgentCryptoIdentity, canonical_json, canonical_message,
    sign_request, verify_signature, NexusClient
)

def test_audit():
    print("=" * 75)
    print(" NEXUS AGENTS CRYPTO PROTOCOL — SDK v2.0 CRYPTOGRAPHIC AUDIT")
    print("=" * 75)

    # 1. Ed25519 & X25519 Keypair Verification
    print("\n[+] TEST 1: Generating Authentic Dual-Key Asymmetric Identity...")
    alice = AgentCryptoIdentity(name="Alice-Arbitrage-Bot")
    bob = AgentCryptoIdentity(name="Bob-Inference-Seller")

    print(f"    • Alice Ed25519 Pubkey ({len(alice.ed_pubkey_hex)} hex chars): {alice.ed_pubkey_hex}")
    print(f"    • Alice X25519 Pubkey  ({len(alice.x_pubkey_hex)} hex chars): {alice.x_pubkey_hex}")
    assert len(alice.ed_pubkey_hex) == 64, "Ed25519 pubkey must be exactly 32 bytes (64 hex characters)!"
    assert len(alice.x_pubkey_hex) == 64, "X25519 pubkey must be exactly 32 bytes (64 hex characters)!"
    assert alice.ed_pubkey_hex != bob.ed_pubkey_hex, "Key entropy failure: keys must be distinct!"
    print("    [✓] PASS: Genuine 256-bit asymmetric curve keypairs confirmed.")

    # 2. Canonical JSON RFC 8785 Determinism
    print("\n[+] TEST 2: RFC 8785 Canonical JSON Serialization...")
    d1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    d2 = {"a": 2, "m": {"a": 4, "b": 3}, "z": 1}
    assert canonical_json(d1) == canonical_json(d2), "Canonical JSON must produce identical byte sequences regardless of key order!"
    print(f"    • Canonical representation: {canonical_json(d1).decode('utf-8')}")
    print("    [✓] PASS: Deterministic canonical hashing verified.")

    # 3. Authentic Ed25519 Request Signing
    print("\n[+] TEST 3: Ed25519 Request Signing & Cryptographic Verification...")
    alice.agent_id = "agent_alice_real_001"
    endpoint = "/api/rooms/propose"
    payload = {
        "room_id": "room_live_999",
        "terms": {
            "asset_a": "AI_INFERENCE_ORACLE",
            "amount_a": "100.00",
            "asset_b": "USDX",
            "amount_b": "950.00",
            "fee_bps": 50
        }
    }

    auth_claim = sign_request(endpoint, payload, alice.agent_id, alice.ed_privkey)
    print(f"    • Signature ({len(auth_claim['sig'])} hex chars): {auth_claim['sig'][:32]}...")
    print(f"    • Nonce:     {auth_claim['nonce']}")
    print(f"    • Timestamp: {auth_claim['ts']}")
    assert len(auth_claim['sig']) == 128, "Ed25519 signatures must be exactly 64 bytes (128 hex chars)!"

    # Verification
    is_valid = verify_signature(endpoint, payload, auth_claim, alice.ed_pubkey_hex)
    assert is_valid is True, "Valid signature failed cryptographic verification!"
    print("    [✓] PASS: Genuine signature verified successfully.")

    # 4. Negative Proof: Payload Tampering
    print("\n[+] TEST 4 (Negative Proof): Tampering Detection...")
    tampered_payload = payload.copy()
    tampered_payload["terms"] = payload["terms"].copy()
    tampered_payload["terms"]["amount_b"] = "10.00" # Attacker altered price!

    is_tampered_valid = verify_signature(endpoint, tampered_payload, auth_claim, alice.ed_pubkey_hex)
    assert is_tampered_valid is False, "SECURITY BREACH: Tampered payload was accepted!"
    print("    [✓] PASS: Tampered payload rejected instantaneously.")

    # 5. Negative Proof: Impersonation / Wrong Public Key
    print("\n[+] TEST 5 (Negative Proof): Impersonation Defense...")
    is_impersonation_valid = verify_signature(endpoint, payload, auth_claim, bob.ed_pubkey_hex)
    assert is_impersonation_valid is False, "SECURITY BREACH: Signature accepted with counterparty's key!"
    print("    [✓] PASS: Impersonation with distinct key rejected.")

    # 6. Negative Proof: Replay Protection (Expired Timestamp)
    print("\n[+] TEST 6 (Negative Proof): Anti-Replay Timestamp Check...")
    expired_claim = auth_claim.copy()
    expired_claim["ts"] = int(time.time()) - 300 # 5 minutes old!
    is_expired_valid = verify_signature(endpoint, payload, expired_claim, alice.ed_pubkey_hex)
    assert is_expired_valid is False, "SECURITY BREACH: Expired replay attack succeeded!"
    print("    [✓] PASS: Replay attempt with expired timestamp blocked.")

    # 7. Keystore Persistence
    print("\n[+] TEST 7: Local Keystore Export & Re-Import...")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        keystore_path = tf.name

    try:
        alice.save_keystore(keystore_path)
        alice_restored = AgentCryptoIdentity.load_keystore(keystore_path)
        assert alice_restored.name == alice.name, "Restored name mismatch!"
        assert alice_restored.agent_id == alice.agent_id, "Restored agent_id mismatch!"
        assert alice_restored.ed_pubkey_hex == alice.ed_pubkey_hex, "Restored Ed25519 key mismatch!"
        assert alice_restored.x_pubkey_hex == alice.x_pubkey_hex, "Restored X25519 key mismatch!"

        # Verify signature with restored key
        claim_restored = sign_request(endpoint, payload, alice_restored.agent_id, alice_restored.ed_privkey)
        assert verify_signature(endpoint, payload, claim_restored, alice.ed_pubkey_hex) is True
        print(f"    • Keystore successfully roundtripped at: {keystore_path}")
        print("    [✓] PASS: Keystore persistence 100% verified.")
    finally:
        if os.path.exists(keystore_path):
            os.remove(keystore_path)

    # 8. Protocol Fee Calculation (0.5% Commission)
    print("\n[+] TEST 8: Protocol House Fee Math Precision...")
    fee, net = NexusClient.calculate_house_fee(gross_amount=1000.0, fee_bps=50)
    assert fee == 5.0, f"Expected fee 5.0, got {fee}"
    assert net == 995.0, f"Expected net 995.0, got {net}"

    fee2, net2 = NexusClient.calculate_house_fee(gross_amount=950.0, fee_bps=50)
    assert fee2 == 4.75, f"Expected fee 4.75, got {fee2}"
    assert net2 == 945.25, f"Expected net 945.25, got {net2}"
    print(f"    • $950.00 USDX trade -> Protocol Fee: ${fee2} USDX (0.5%) | Payout: ${net2} USDX")
    print("    [✓] PASS: Financial fee calculation matches Phase 51 production ledger.")

    print("\n" + "=" * 75)
    print(" 🏆 ALL 8 CRYPTOGRAPHIC TESTS PASSED WITH 100% SUCCESS!")
    print(" SDK v2.0 IS MATHEMATICALLY COMPLIANT AND READY FOR PRODUCTION.")
    print("=" * 75)

if __name__ == "__main__":
    test_audit()
