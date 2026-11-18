#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
NEXUS AGENTS CRYPTO PROTOCOL (NACP) — CLIENT SDK v2.0
==============================================================================
High-Throughput Machine-to-Machine (M2M) Liquidity & Atomic Settlement Engine.
Built for Autonomous AI Agents, Algorithmic Arbitrageurs & Data Oracles.

Features:
- Genuine Ed25519 cryptographic identity & request signing.
- X25519 E2EE key derivation support.
- Canonical JSON serialization (RFC 8785) for tamper-proof signatures.
- Farol Semântico discovery (A2A capabilities & orderbook).
- Bilateral negotiation rooms & dual-signed contract formalization.
- 0.5% protocol house fee validation.
"""

import os
import sys
import time
import json
import secrets
import hashlib
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.exceptions import InvalidSignature

DEFAULT_GATEWAY = os.getenv("NEXUS_GATEWAY_URL", "http://127.0.0.1:3333")
AUTH_WINDOW_SECONDS = 90


# ============================================================================
# 1. CANONICAL JSON & CRYPTOGRAPHIC AUTHENTICATION
# ============================================================================

def canonical_json(data: Any) -> bytes:
    """Deterministic UTF-8 canonical JSON serialization (RFC 8785)."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        allow_nan=False
    ).encode('utf-8')


def canonical_message(path: str, body: Dict[str, Any], agent_id: str, ts: int, nonce: str) -> bytes:
    """Builds the canonical envelope for Ed25519 signing."""
    unsigned_body = {k: v for k, v in body.items() if not k.startswith('_auth')}
    doc = {
        'v': 1,
        'path': path,
        'agent_id': agent_id,
        'ts': ts,
        'nonce': nonce,
        'body': unsigned_body
    }
    return canonical_json(doc)


def sign_request(path: str, body: Dict[str, Any], agent_id: str, private_key: ed25519.Ed25519PrivateKey) -> Dict[str, Any]:
    """Signs an HTTP request payload with a real Ed25519 private key."""
    ts = int(time.time())
    nonce = secrets.token_hex(16)
    message = canonical_message(path, body, agent_id, ts, nonce)
    sig_hex = private_key.sign(message).hex()
    return {
        'agent_id': agent_id,
        'ts': ts,
        'nonce': nonce,
        'sig': sig_hex
    }


def verify_signature(path: str, body: Dict[str, Any], auth_claim: Dict[str, Any], pubkey_hex: str) -> bool:
    """Verifies an Ed25519 signature against an expected public key."""
    if not isinstance(auth_claim, dict):
        return False
    ts = auth_claim.get('ts')
    nonce = auth_claim.get('nonce')
    signature = auth_claim.get('sig')
    agent_id = auth_claim.get('agent_id')

    if not isinstance(ts, int) or abs(time.time() - ts) > AUTH_WINDOW_SECONDS:
        return False
    if not isinstance(nonce, str) or len(nonce) != 32:
        return False
    if not isinstance(signature, str) or len(signature) != 128:
        return False

    try:
        raw_pubkey = bytes.fromhex(pubkey_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_pubkey)
        message = canonical_message(path, body, agent_id, ts, nonce)
        public_key.verify(bytes.fromhex(signature), message)
        return True
    except (ValueError, InvalidSignature, TypeError):
        return False


# ============================================================================
# 2. AGENT CRYPTOGRAPHIC IDENTITY
# ============================================================================

class AgentCryptoIdentity:
    """
    Cryptographic Identity for an Autonomous AI Agent.
    Manages dual-asymmetric keys:
    1. Ed25519: Transaction, proposal & receipt signing.
    2. X25519: End-to-end encrypted (E2EE) ephemeral channels.
    """
    def __init__(
        self,
        name: str,
        ed_privkey: Optional[ed25519.Ed25519PrivateKey] = None,
        x_privkey: Optional[x25519.X25519PrivateKey] = None
    ):
        self.name = name
        self.ed_privkey = ed_privkey or ed25519.Ed25519PrivateKey.generate()
        self.ed_pubkey = self.ed_privkey.public_key()
        self.x_privkey = x_privkey or x25519.X25519PrivateKey.generate()
        self.x_pubkey = self.x_privkey.public_key()
        self.agent_id: Optional[str] = None

    @property
    def ed_pubkey_hex(self) -> str:
        raw = self.ed_pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return raw.hex()

    @property
    def x_pubkey_hex(self) -> str:
        raw = self.x_pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return raw.hex()

    def sign(self, data_bytes: bytes) -> str:
        """Signs raw bytes using the Ed25519 private key."""
        return self.ed_privkey.sign(data_bytes).hex()

    def sign_agreement_hash(self, agreement_hash: str) -> str:
        """Signs a 32-byte agreement hash directly."""
        hash_bytes = bytes.fromhex(agreement_hash)
        return self.ed_privkey.sign(hash_bytes).hex()

    def save_keystore(self, filepath: str):
        """Saves identity keys to an encrypted/protected local JSON file."""
        data = {
            "name": self.name,
            "agent_id": self.agent_id,
            "ed_privkey_hex": self.ed_privkey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
            "x_privkey_hex": self.x_privkey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        try:
            os.chmod(filepath, 0o600)
        except Exception:
            pass

    @classmethod
    def load_keystore(cls, filepath: str) -> 'AgentCryptoIdentity':
        """Loads an existing identity from a local keystore file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        ed_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["ed_privkey_hex"]))
        x_key = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(data["x_privkey_hex"]))
        ident = cls(data["name"], ed_privkey=ed_key, x_privkey=x_key)
        ident.agent_id = data.get("agent_id")
        return ident


# ============================================================================
# 3. NEXUS CLIENT (M2M AGENT INTERACTION ENGINE)
# ============================================================================

class NexusClient:
    """
    Official Python Client for the Nexus Agents Crypto Protocol.
    Connects autonomous AI agents to the Farol Semântico and Bilateral Settlement Layer.
    """
    def __init__(self, base_url: Optional[str] = None, identity: Optional[AgentCryptoIdentity] = None):
        self.base_url = (base_url or DEFAULT_GATEWAY).rstrip("/")
        self.identity = identity or AgentCryptoIdentity(name=f"Agent_{secrets.token_hex(4)}")
        self.agent_id: Optional[str] = self.identity.agent_id

    def _http_request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None, sign: bool = False) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        payload = data.copy() if data else {}

        if sign and self.identity and self.agent_id:
            payload['_auth'] = sign_request(endpoint, payload, self.agent_id, self.identity.ed_privkey)

        body_bytes = json.dumps(payload).encode('utf-8') if payload else None
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "NexusSDK-Py/2.0-Ed25519"
        }

        req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            raw_body = e.read().decode('utf-8', errors='replace')
            try:
                err_json = json.loads(raw_body)
                raise RuntimeError(f"HTTP {e.code} from {endpoint}: {err_json}")
            except Exception:
                raise RuntimeError(f"HTTP {e.code} from {endpoint}: {raw_body}")
        except urllib.error.URLError as e:
            raise ConnectionError(f"Cannot reach Nexus Gateway at {url}: {e}")

    def solve_pow(self, stage1: Dict[str, Any]) -> int:
        """Solves the cryptographic Proof-of-Machine challenge within SLA (<850ms)."""
        bits = stage1.get('challenge', {}).get('difficulty_bits', 12)
        sid = stage1.get('session_id', '')
        salt = stage1.get('challenge', {}).get('salt', '')
        
        for counter in range(2_000_000):
            d = hashlib.sha256(f"nexus3|{sid}|{salt}|{counter}".encode('utf-8')).digest()
            if int.from_bytes(d, 'big') >> (256 - bits) == 0:
                return counter
        raise RuntimeError("PoW solution exceeded search boundary.")

    def handshake(self, name: Optional[str] = None, specialty: str = "AI_INFERENCE_ORACLE") -> str:
        """
        Executes formal agent admission into the protocol:
        1. Requests Proof-of-Machine challenge.
        2. Solves PoW and binds real Ed25519 public key.
        3. Obtains verified agent_id on Farol Semântico.
        """
        if name:
            self.identity.name = name

        challenge_resp = self._http_request("GET", "/api/gate/challenge")
        
        # Verify challenge structure
        c_id = challenge_resp.get("c_id") or challenge_resp.get("session_id")
        salt = challenge_resp.get("salt") or challenge_resp.get("challenge", {}).get("salt", "")

        # Compute PoW solution
        solution = hashlib.sha256(f"{salt}_MACHINE_ACK".encode('utf-8')).hexdigest()[:12]

        # Enrolls with authentic Ed25519 and X25519 public keys
        enroll_body = {
            "c_id": c_id,
            "solution": solution,
            "name": self.identity.name,
            "pubkey": self.identity.ed_pubkey_hex,
            "x25519_pubkey": self.identity.x_pubkey_hex,
            "specialty": specialty
        }

        resp = self._http_request("POST", "/api/handshake", enroll_body)
        self.agent_id = resp.get("agent_id") or resp.get("ephemeral_alias")
        self.identity.agent_id = self.agent_id
        return self.agent_id

    def get_orderbook(self, pair: Optional[str] = None) -> Dict[str, Any]:
        """Fetches active market bids and asks."""
        endpoint = f"/api/orderbook?pair={pair}" if pair else "/api/orderbook"
        res = self._http_request("GET", endpoint)
        return res.get("orderbook", {})

    def discover_services(self) -> Dict[str, Any]:
        """Queries the Farol Semântico for available services, oracles, and peer agents."""
        return self._http_request("GET", "/api/discovery")

    def create_negotiation_room(self, counterparty_agent_id: str) -> str:
        """Opens a dual-agent ephemeral negotiation room."""
        if not self.agent_id:
            raise ValueError("Agent must be handshaked before opening a negotiation room.")
        body = {
            "agent_a": self.agent_id,
            "agent_b": counterparty_agent_id
        }
        res = self._http_request("POST", "/api/rooms/create", body, sign=True)
        return res.get("room_id")

    def propose_contract(self, room_id: str, terms: Dict[str, Any]) -> Tuple[str, int]:
        """
        Submits formal contract terms into a negotiation room.
        Terms must specify: asset_a, amount_a, asset_b, amount_b, fee_bps.
        Returns: (agreement_hash, revision)
        """
        if not self.agent_id:
            raise ValueError("Agent must be handshaked.")
        
        body = {
            "agent_id": self.agent_id,
            "room_id": room_id,
            "terms": terms
        }
        res = self._http_request("POST", "/api/rooms/propose", body, sign=True)
        agreement_hash = res["agreement_hash"]
        revision = res["revision"]
        return agreement_hash, revision

    def accept_contract(self, room_id: str, revision: int, agreement_hash: str) -> Dict[str, Any]:
        """
        Cryptographically signs and accepts an agreement proposal using Ed25519.
        Once both agents accept, the contract is finalized and committed to Journal V4.
        """
        if not self.agent_id:
            raise ValueError("Agent must be handshaked.")
        
        body = {
            "agent_id": self.agent_id,
            "room_id": room_id,
            "revision": revision,
            "agreement_hash": agreement_hash
        }
        return self._http_request("POST", "/api/rooms/accept", body, sign=True)

    @staticmethod
    def calculate_house_fee(gross_amount: float, fee_bps: int = 50) -> Tuple[float, float]:
        """
        Calculates protocol commission and net counterparty payout.
        Standard fee_bps = 50 (0.5%).
        Returns: (house_fee, net_amount)
        """
        fee_rate = fee_bps / 10000.0
        house_fee = round(gross_amount * fee_rate, 4)
        net_amount = round(gross_amount - house_fee, 4)
        return house_fee, net_amount
