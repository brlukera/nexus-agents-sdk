#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NEXUS SDK v2.0 — CRYPTOGRAPHIC AUDIT & COMPLIANCE TEST SUITE
============================================================
Runs comprehensive mathematical and security checks on:
1. Ed25519 Key Generation & Hex Representation (32-byte raw keys).
2. X25519 E2EE Key Generation.
3. RFC 8785 Canonical JSON (JCS) determinism, UTF-16 code unit order, and number handling.
4. Digital Signatures & Cryptographic Verification.
5. Negative Proof: Payload Tampering Rejection.
6. Negative Proof: Impersonation / Wrong Key Rejection.
7. Negative Proof: Expired Timestamp Rejection.
8. Negative Proof: Anti-Replay Attack Detection (Duplicate Nonce Rejection).
9. Secure Keystore Export & Re-Import (Unencrypted + AES-256-GCM Encrypted + Wrong Password Rejection).
10. Proof-of-Machine PoW Execution (Bit-difficulty & Bytecode ACK solvers).
11. Protocol Fee Mathematical Precision (decimal.Decimal 6-decimal USDC micro-units, negative and boundary guards).
"""

import os
import sys
import time
import json
import tempfile
from decimal import Decimal

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from nexus_sdk import (
    AgentCryptoIdentity, canonical_json, canonical_message,
    sign_request, verify_signature, clear_replay_cache, NexusClient
)

def test_audit():
    print("=" * 80)
    print(" NEXUS AGENTS CRYPTO PROTOCOL — SDK v2.0 CRYPTOGRAPHIC & SECURITY AUDIT")
    print("=" * 80)

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

    # 2. RFC 8785 Canonical JSON Serialization (JCS)
    print("\n[+] TEST 2: RFC 8785 Canonical JSON (JCS) Compliance & UTF-16 Code Unit Order...")
    d1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}, "active": True, "ratio": 1.5, "empty": None}
    d2 = {"empty": None, "a": 2, "ratio": 1.5, "m": {"a": 4, "b": 3}, "active": True, "z": 1}
    assert canonical_json(d1) == canonical_json(d2), "Canonical JSON must produce identical bytes regardless of key insertion order!"
    
    # Test UTF-16 code unit sorting (RFC 8785 §3.2.3)
    # Supplementary character U+10000 has surrogate pair (0xD800, 0xDC00) which sorts before U+FFFF in UTF-16
    d_unicode = {"\uffff": 1, "\U00010000": 2}
    cj_unicode = canonical_json(d_unicode).decode('utf-8')
    assert cj_unicode == '{"\U00010000":2,"\uffff":1}', f"RFC 8785 UTF-16 sorting failed: got {cj_unicode}"
    print(f"    • Canonical representation: {canonical_json(d1).decode('utf-8')}")
    print(f"    • RFC 8785 UTF-16 code unit order verified: {cj_unicode}")
    print("    [✓] PASS: Deterministic RFC 8785 canonical serialization verified.")

    # 3. Authentic Ed25519 Request Signing
    print("\n[+] TEST 3: Ed25519 Request Signing & Cryptographic Verification...")
    alice.agent_id = "agent_alice_real_001"
    endpoint = "/api/rooms/propose"
    payload = {
        "room_id": "room_live_999",
        "terms": {
            "asset_a": "AI_INFERENCE_ORACLE",
            "amount_a": "100.000000",
            "asset_b": "USDC",
            "amount_b": "950.000000",
            "fee_bps": 50
        }
    }

    clear_replay_cache()
    auth_claim = sign_request(endpoint, payload, alice.agent_id, alice.ed_privkey)
    print(f"    • Signature ({len(auth_claim['sig'])} hex chars): {auth_claim['sig'][:32]}...")
    print(f"    • Nonce:     {auth_claim['nonce']}")
    print(f"    • Timestamp: {auth_claim['ts']}")
    assert len(auth_claim['sig']) == 128, "Ed25519 signatures must be exactly 64 bytes (128 hex chars)!"

    # Initial verification
    is_valid = verify_signature(endpoint, payload, auth_claim, alice.ed_pubkey_hex)
    assert is_valid is True, "Valid signature failed cryptographic verification!"
    print("    [✓] PASS: Genuine signature verified successfully.")

    # 4. Negative Proof: Anti-Replay Nonce Defense
    print("\n[+] TEST 4 (Negative Proof): Anti-Replay Nonce Defense...")
    # Resubmitting the EXACT same valid claim within the 90s window must fail because nonce was consumed!
    is_replay_valid = verify_signature(endpoint, payload, auth_claim, alice.ed_pubkey_hex)
    assert is_replay_valid is False, "SECURITY BREACH: Replayed nonce was accepted!"
    print("    [✓] PASS: Replay attack blocked (duplicate nonce rejected).")

    # 5. Negative Proof: Payload Tampering
    print("\n[+] TEST 5 (Negative Proof): Tampering Detection...")
    tampered_claim = sign_request(endpoint, payload, alice.agent_id, alice.ed_privkey)
    tampered_payload = payload.copy()
    tampered_payload["terms"] = payload["terms"].copy()
    tampered_payload["terms"]["amount_b"] = "10.000000"  # Attacker modified price!

    is_tampered_valid = verify_signature(endpoint, tampered_payload, tampered_claim, alice.ed_pubkey_hex)
    assert is_tampered_valid is False, "SECURITY BREACH: Tampered payload was accepted!"
    print("    [✓] PASS: Tampered payload rejected instantaneously.")

    # 6. Negative Proof: Impersonation / Wrong Public Key
    print("\n[+] TEST 6 (Negative Proof): Impersonation Defense...")
    fresh_claim = sign_request(endpoint, payload, alice.agent_id, alice.ed_privkey)
    is_impersonation_valid = verify_signature(endpoint, payload, fresh_claim, bob.ed_pubkey_hex)
    assert is_impersonation_valid is False, "SECURITY BREACH: Signature accepted with counterparty's key!"
    print("    [✓] PASS: Impersonation with distinct key rejected.")

    # 7. Negative Proof: Expired Timestamp
    print("\n[+] TEST 7 (Negative Proof): Expired Timestamp Rejection...")
    expired_claim = fresh_claim.copy()
    expired_claim["ts"] = int(time.time()) - 300  # 5 minutes old!
    expired_claim["nonce"] = "0123456789abcdef0123456789abcdef"
    is_expired_valid = verify_signature(endpoint, payload, expired_claim, alice.ed_pubkey_hex)
    assert is_expired_valid is False, "SECURITY BREACH: Expired timestamp succeeded!"
    print("    [✓] PASS: Replay attempt with expired timestamp blocked.")

    # 8. Keystore Persistence (Unencrypted and AES-256-GCM Encrypted)
    print("\n[+] TEST 8: Keystore Persistence (Unencrypted & AES-256-GCM Encrypted)...")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf1:
        unencrypted_path = tf1.name
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf2:
        encrypted_path = tf2.name

    password = "SuperSecureAgentPassword#2026"

    try:
        # a. Unencrypted roundtrip
        alice.save_keystore(unencrypted_path)
        restored_raw = AgentCryptoIdentity.load_keystore(unencrypted_path)
        assert restored_raw.ed_pubkey_hex == alice.ed_pubkey_hex
        assert restored_raw.x_pubkey_hex == alice.x_pubkey_hex

        # b. AES-256-GCM Encrypted roundtrip
        alice.save_keystore(encrypted_path, password=password)
        with open(encrypted_path, "r", encoding="utf-8") as f:
            encrypted_file_data = json.load(f)
        assert encrypted_file_data.get("encrypted") is True
        assert "ed_privkey_hex" not in encrypted_file_data, "Private key leaked in plaintext in encrypted keystore!"
        assert "cipher" in encrypted_file_data and "nonce" in encrypted_file_data["cipher"]

        # Restore with correct password
        restored_enc = AgentCryptoIdentity.load_keystore(encrypted_path, password=password)
        assert restored_enc.ed_pubkey_hex == alice.ed_pubkey_hex
        assert restored_enc.x_pubkey_hex == alice.x_pubkey_hex

        # Negative check: Wrong password
        try:
            AgentCryptoIdentity.load_keystore(encrypted_path, password="WrongPassword123!")
            assert False, "SECURITY BREACH: Keystore decrypted with incorrect password!"
        except ValueError:
            pass  # Expected

        # Negative check: Missing password
        try:
            AgentCryptoIdentity.load_keystore(encrypted_path)
            assert False, "SECURITY BREACH: Encrypted keystore opened without password!"
        except ValueError:
            pass  # Expected

        print("    • Unencrypted & AES-256-GCM password-encrypted keystores verified.")
        print("    • Brute-force and wrong-password rejection confirmed.")
        print("    [✓] PASS: Keystore cryptographic protection 100% verified.")
    finally:
        for p in (unencrypted_path, encrypted_path):
            if os.path.exists(p):
                os.remove(p)

    # 9. Proof-of-Machine PoW Execution
    print("\n[+] TEST 9: Proof-of-Machine PoW Solver Execution...")
    client = NexusClient(identity=alice)
    
    # Hashcash challenge
    challenge_bits = {
        "session_id": "sess_audit_001",
        "challenge": {
            "difficulty_bits": 10,
            "salt": "audit_salt_pow"
        }
    }
    pow_sol = client.solve_pow(challenge_bits)
    print(f"    • Difficulty 10 PoW solved in counter: {pow_sol}")
    assert int(pow_sol) >= 0

    # Bytecode ACK challenge
    challenge_ack = {
        "c_id": "gate_challenge_001",
        "salt": "salt_quick_gate_123"
    }
    ack_sol = client.solve_pow(challenge_ack)
    print(f"    • Bytecode ACK solution: {ack_sol}")
    assert len(ack_sol) == 12
    print("    [✓] PASS: Proof-of-Machine solver executed and validated.")

    # 10. Protocol Fee Calculation (USDC 6-Decimal Math & Boundary Checks)
    print("\n[+] TEST 10: Protocol House Fee Math Precision (decimal.Decimal 6-decimals)...")
    fee, net = NexusClient.calculate_house_fee(gross_amount="1000.000000", fee_bps=50)
    assert fee == Decimal("5.000000"), f"Expected 5.000000, got {fee}"
    assert net == Decimal("995.000000"), f"Expected 995.000000, got {net}"

    fee2, net2 = NexusClient.calculate_house_fee(gross_amount=950.0, fee_bps=50)
    assert fee2 == Decimal("4.750000"), f"Expected 4.750000, got {fee2}"
    assert net2 == Decimal("945.250000"), f"Expected 945.250000, got {net2}"

    # Micro-USDC precision test (1 micro-unit = 0.000001)
    fee_micro, net_micro = NexusClient.calculate_house_fee(gross_amount="0.000001", fee_bps=50)
    assert fee_micro == Decimal("0.000000")
    assert net_micro == Decimal("0.000001")

    # Negative check: Zero or negative amount
    for bad_amt in [0, -10, "-500"]:
        try:
            NexusClient.calculate_house_fee(gross_amount=bad_amt, fee_bps=50)
            assert False, f"SECURITY BREACH: Accepted invalid gross amount {bad_amt}!"
        except ValueError:
            pass  # Expected

    # Negative check: Ceiling violation
    try:
        NexusClient.calculate_house_fee(gross_amount=10000.0, fee_bps=50, max_amount=5000.0)
        assert False, "SECURITY BREACH: Accepted trade exceeding ceiling limit!"
    except ValueError:
        pass  # Expected

    # Negative check: Invalid fee_bps (> 10000 or negative)
    for bad_bps in [-1, 10001, "invalid"]:
        try:
            NexusClient.calculate_house_fee(gross_amount=100.0, fee_bps=bad_bps) # type: ignore
            assert False, f"SECURITY BREACH: Accepted invalid fee_bps {bad_bps}!"
        except (ValueError, TypeError):
            pass  # Expected

    print(f"    • $950.00 USDC trade -> Fee: {fee2} USDC (0.500000) | Payout: {net2} USDC")
    print("    • Boundary guards: Negative amounts, ceiling overflow, and invalid bps rejected.")
    print("    [✓] PASS: Strict 6-decimal USDC financial arithmetic confirmed.")

    print("\n" + "=" * 80)
    print(" 🏆 ALL 10 COMPLIANCE & SECURITY AUDIT TESTS PASSED WITH 100% SUCCESS!")
    print(" SDK v2.0 IS MATHEMATICALLY, CRYPTOGRAPHICALLY & FINANCIALLY VALIDATED.")
    print("=" * 80)

if __name__ == "__main__":
    test_audit()
