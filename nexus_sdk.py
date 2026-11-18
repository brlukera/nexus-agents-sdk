#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
NEXUS AGENTS CRYPTO PROTOCOL (NACP) — CLIENT SDK v2.0.1
==============================================================================
High-Throughput Machine-to-Machine (M2M) Liquidity & Atomic Settlement Engine.
Built for Autonomous AI Agents, Algorithmic Arbitrageurs & Data Oracles.

Features:
- Genuine Ed25519 cryptographic identity & request signing.
- X25519 E2EE key derivation support.
- Strict RFC 8785 Canonical JSON serialization (JCS) with official vector compliance.
- Thread-safe atomic anti-replay protection (concurrency race-free & DoS resilient).
- Machine-grade Proof-of-Work (PoW) solver for protocol admission.
- Secure keystore with optional AES-256-GCM password encryption.
- Financial arithmetic in decimal.Decimal with 6 decimal places (USDC micro-units).
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
import threading
import urllib.request
import urllib.error
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from typing import Dict, Any, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature, InvalidTag

DEFAULT_GATEWAY = os.getenv("NEXUS_GATEWAY_URL", "http://127.0.0.1:3333")
AUTH_WINDOW_SECONDS = 90
USDC_PRECISION = Decimal('0.000001')


# ============================================================================
# 1. CANONICAL JSON (RFC 8785 / JCS) & CRYPTOGRAPHIC AUTHENTICATION
# ============================================================================

def _rfc8785_encode(val: Any) -> str:
    """
    RFC 8785 (JSON Canonicalization Scheme - JCS) recursive encoder.
    Enforces:
    1. Lexicographical sorting of object keys by UTF-16 code units (§3.2.3).
    2. Deterministic whitespace rules (§3.2.1).
    3. IEEE 754 number representation and rejection of NaN/Infinity (§3.2.2).
    """
    if val is None:
        return "null"
    elif isinstance(val, bool):
        return "true" if val else "false"
    elif isinstance(val, int):
        return str(val)
    elif isinstance(val, float):
        if val != val or val == float('inf') or val == float('-inf'):
            raise ValueError("NaN and Infinity are not permitted in RFC 8785 canonical JSON")
        if val == 0.0:
            return "0"
        if val.is_integer():
            return str(int(val))
        return json.dumps(val)
    elif isinstance(val, Decimal):
        if val.is_nan() or val.is_infinite():
            raise ValueError("NaN and Infinity are not permitted in RFC 8785 canonical JSON")
        return str(val)
    elif isinstance(val, str):
        return json.dumps(val, ensure_ascii=False)
    elif isinstance(val, (list, tuple)):
        return "[" + ",".join(_rfc8785_encode(x) for x in val) + "]"
    elif isinstance(val, dict):
        # RFC 8785 §3.2.3: Keys must be sorted by UTF-16 code units
        sorted_keys = sorted(val.keys(), key=lambda k: k.encode('utf-16-be'))
        items = []
        for k in sorted_keys:
            if not isinstance(k, str):
                raise TypeError(f"RFC 8785 dictionary keys must be strings, got {type(k)}")
            k_json = json.dumps(k, ensure_ascii=False)
            v_json = _rfc8785_encode(val[k])
            items.append(f"{k_json}:{v_json}")
        return "{" + ",".join(items) + "}"
    else:
        raise TypeError(f"RFC 8785 unsupported type: {type(val)}")


def canonical_json(data: Any) -> bytes:
    """Deterministic UTF-8 canonical JSON serialization strictly compliant with RFC 8785."""
    return _rfc8785_encode(data).encode('utf-8')


# Anti-Replay TTL Nonce Cache
_SEEN_NONCES: Dict[str, float] = {}
_NONCE_LOCK = threading.Lock()


def clear_replay_cache() -> None:
    """Clears the local anti-replay cache (used for test suite isolation)."""
    with _NONCE_LOCK:
        _SEEN_NONCES.clear()


def _purge_expired_nonces(now: float) -> None:
    cutoff = now - AUTH_WINDOW_SECONDS
    expired = [k for k, ts in _SEEN_NONCES.items() if ts < cutoff]
    for k in expired:
        _SEEN_NONCES.pop(k, None)


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
    """
    Verifies an Ed25519 signature against an expected public key.
    Enforces a strict 90-second timestamp window and atomic thread-safe anti-replay cache.

    Security flow:
    1. Structure and timestamp validation.
    2. Ed25519 cryptographic verification FIRST (prevents DoS/frontrunning of legitimate nonces).
    3. Atomic thread-lock acquisition:
       - Purge expired nonces (>90s).
       - Check if nonce already exists in seen cache.
       - If seen, reject (replay attack blocked).
       - If fresh, immediately insert nonce into cache.
    4. Release lock and accept request.
    """
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
    if not isinstance(agent_id, str) or not agent_id:
        return False

    # 1. Validar assinatura criptográfica PRIMEIRO (evita DoS em nonces legítimos)
    try:
        raw_pubkey = bytes.fromhex(pubkey_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_pubkey)
        message = canonical_message(path, body, agent_id, ts, nonce)
        public_key.verify(bytes.fromhex(signature), message)
    except (ValueError, InvalidSignature, TypeError):
        return False

    # 2. Entrar no thread-lock atômico para verificar e reservar o nonce
    now = time.time()
    nonce_key = f"{agent_id}:{nonce}"
    with _NONCE_LOCK:
        # 3. Remover nonces expirados
        _purge_expired_nonces(now)
        # 4. Verificar se o nonce já foi consumido
        if nonce_key in _SEEN_NONCES:
            return False  # REPLAY ATTACK BLOCKED: Nonce já utilizado!
        # 5. Inserir imediatamente no mesmo lock
        _SEEN_NONCES[nonce_key] = now

    # 6. Liberar lock e aceitar requisição
    return True


# ============================================================================
# 2. AGENT CRYPTOGRAPHIC IDENTITY & SECURE KEYSTORE
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

    def save_keystore(self, filepath: str, password: Optional[str] = None) -> None:
        """
        Saves identity keys to a local JSON keystore.
        If password is provided, private keys are encrypted using AES-256-GCM
        with key derivation via PBKDF2-HMAC-SHA256 (100,000 iterations).
        If password is None, keys are saved unencrypted with explicit metadata.
        """
        ed_raw = self.ed_privkey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
        x_raw = self.x_privkey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()

        if password:
            salt = secrets.token_bytes(16)
            nonce = secrets.token_bytes(12)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100_000
            )
            derived_key = kdf.derive(password.encode('utf-8'))
            aesgcm = AESGCM(derived_key)
            secret_payload = json.dumps({
                "ed_privkey_hex": ed_raw,
                "x_privkey_hex": x_raw
            }).encode('utf-8')
            ciphertext = aesgcm.encrypt(nonce, secret_payload, None)

            keystore_data = {
                "version": 2,
                "encrypted": True,
                "name": self.name,
                "agent_id": self.agent_id,
                "ed_pubkey_hex": self.ed_pubkey_hex,
                "x_pubkey_hex": self.x_pubkey_hex,
                "kdf": {
                    "algorithm": "PBKDF2-HMAC-SHA256",
                    "iterations": 100_000,
                    "salt": salt.hex()
                },
                "cipher": {
                    "algorithm": "AES-256-GCM",
                    "nonce": nonce.hex(),
                    "ciphertext": ciphertext.hex()
                },
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        else:
            keystore_data = {
                "version": 2,
                "encrypted": False,
                "name": self.name,
                "agent_id": self.agent_id,
                "ed_pubkey_hex": self.ed_pubkey_hex,
                "x_pubkey_hex": self.x_pubkey_hex,
                "ed_privkey_hex": ed_raw,
                "x_privkey_hex": x_raw,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(keystore_data, f, indent=2)

        try:
            os.chmod(filepath, 0o600)
        except Exception:
            pass

    @classmethod
    def load_keystore(cls, filepath: str, password: Optional[str] = None) -> 'AgentCryptoIdentity':
        """
        Loads an agent identity from a local keystore file.
        Decrypts private keys using AES-256-GCM if password-protected.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        is_encrypted = data.get("encrypted", False)
        if is_encrypted:
            if not password:
                raise ValueError("Keystore is password-encrypted; password is required to decrypt.")

            kdf_info = data.get("kdf", {})
            cipher_info = data.get("cipher", {})
            salt = bytes.fromhex(kdf_info["salt"])
            iterations = kdf_info.get("iterations", 100_000)
            nonce = bytes.fromhex(cipher_info["nonce"])
            ciphertext = bytes.fromhex(cipher_info["ciphertext"])

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations
            )
            derived_key = kdf.derive(password.encode('utf-8'))
            aesgcm = AESGCM(derived_key)
            try:
                decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
                secrets_dict = json.loads(decrypted_bytes.decode('utf-8'))
                ed_raw_hex = secrets_dict["ed_privkey_hex"]
                x_raw_hex = secrets_dict["x_privkey_hex"]
            except (InvalidTag, Exception):
                raise ValueError("Invalid password or corrupt keystore data.")
        else:
            ed_raw_hex = data["ed_privkey_hex"]
            x_raw_hex = data["x_privkey_hex"]

        ed_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ed_raw_hex))
        x_key = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(x_raw_hex))
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

    def solve_pow(self, challenge_resp: Dict[str, Any]) -> str:
        """
        Solves the cryptographic Proof-of-Machine challenge within SLA (<850ms).
        Handles both:
        1. Difficulty-bits Hashcash challenge (difficulty_bits >= 8).
        2. High-throughput Bytecode ACK evaluation (opcode == '0x534841323536_BYTECODE_EVAL').
        """
        ch = challenge_resp.get('challenge', {})
        bits = ch.get('difficulty_bits') or challenge_resp.get('difficulty_bits')
        sid = challenge_resp.get('session_id') or challenge_resp.get('c_id', '')
        salt = ch.get('salt') or challenge_resp.get('salt', '')

        if bits:
            for counter in range(2_000_000):
                d = hashlib.sha256(f"nexus3|{sid}|{salt}|{counter}".encode('utf-8')).digest()
                if int.from_bytes(d, 'big') >> (256 - int(bits)) == 0:
                    return str(counter)
            raise RuntimeError("PoW solution exceeded search boundary.")

        # Bytecode ACK challenge calculation
        return hashlib.sha256(f"{salt}_MACHINE_ACK".encode('utf-8')).hexdigest()[:12]

    def handshake(self, name: Optional[str] = None, specialty: str = "AI_INFERENCE_ORACLE") -> str:
        """
        Executes formal agent admission into the protocol:
        1. Requests Proof-of-Machine challenge from the Gateway.
        2. Solves PoW via self.solve_pow() within SLA window.
        3. Enrolls with authentic Ed25519 & X25519 public keys.
        4. Obtains verified agent_id on Farol Semântico.
        """
        if name:
            self.identity.name = name

        challenge_resp = self._http_request("GET", "/api/gate/challenge")
        c_id = challenge_resp.get("c_id") or challenge_resp.get("session_id")

        # Genuine Proof-of-Machine invocation
        solution = self.solve_pow(challenge_resp)

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
    def calculate_house_fee(
        gross_amount: Union[Decimal, float, str, int],
        fee_bps: int = 50,
        max_amount: Optional[Union[Decimal, float, str, int]] = 5000
    ) -> Tuple[Decimal, Decimal]:
        """
        Calculates protocol commission and net counterparty payout with strict
        6-decimal USDC precision (micro-unit accuracy) using decimal.Decimal.

        Default fee_bps = 50 (0.50% / 50 basis points).

        Validations:
        - gross_amount must be strictly positive (> 0).
        - gross_amount must not exceed max_amount ceiling (default $5,000 USDC).
        - fee_bps must be between 0 and 10,000 (0% to 100%).

        Returns: (house_fee, net_amount) as Decimals rounded with ROUND_HALF_UP.
        """
        try:
            gross = Decimal(str(gross_amount))
        except (InvalidOperation, TypeError, ValueError):
            raise ValueError(f"Invalid gross_amount: {gross_amount}")

        if gross <= Decimal('0'):
            raise ValueError(f"Gross amount must be strictly positive (> 0), got: {gross}")

        if max_amount is not None:
            max_d = Decimal(str(max_amount))
            if gross > max_d:
                raise ValueError(f"Gross amount {gross} exceeds protocol ceiling of {max_d} USDC")

        if not isinstance(fee_bps, int) or fee_bps < 0 or fee_bps > 10000:
            raise ValueError(f"Invalid fee_bps: {fee_bps}. Must be an integer between 0 and 10000.")

        fee_rate = Decimal(fee_bps) / Decimal(10000)
        house_fee = (gross * fee_rate).quantize(USDC_PRECISION, rounding=ROUND_HALF_UP)
        net_amount = (gross - house_fee).quantize(USDC_PRECISION, rounding=ROUND_HALF_UP)
        return house_fee, net_amount
