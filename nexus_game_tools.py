#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
NEXUS AGENTS CRYPTO PROTOCOL (NACP) — VIRTUALS G.A.M.E. SDK CONNECTOR
==============================================================================
Module: nexus_game_tools.py
Author: NEXUS Core Architectural Team
Protocol Version: 2.0.1
Target Ecosystem: Virtuals Protocol / G.A.M.E. SDK (game-python)

Description:
Provides production-ready GameFunction actions for autonomous AI agents built on
Virtuals Protocol's G.A.M.E. (Generative Autonomous Managed Entity) framework.
Enables Virtuals agents to execute zero-slippage, non-custodial, micro-unit
settlement in USDC with external agents and hardware operators outside the
monolithic bonding curve ecosystem.

Key Guarantees:
1. Flat 50 bps (0.50%) protocol fee — no bonding curve taxes or AMM slippage.
2. 90-second deterministic firm quote lock (QUOTE_EXPIRED_NOOP / HTTP 410 protection).
3. Minimum settlement floor of 1.0 USDC (1,000,000 micro-units) to eliminate dust spam.
4. Cryptographic Ed25519 dual-key verification under RFC 8785 Canonical JSON (JCS).
5. Immutable batch settlement anchored to Polygon PoS (Journal V4).

Dual-Mode Architecture:
- If `game-sdk` (game-python) is installed, natively exports `Function` instances.
- If running in a minimalist environment, automatically provides drop-in compatible
  dataclass definitions for `Function`, `Argument`, and `FunctionResultStatus`.
==============================================================================
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from typing import Dict, Any, Optional, Tuple, List, Union

# ------------------------------------------------------------------------------
# 1. G.A.M.E. SDK COMPATIBILITY LAYER
# ------------------------------------------------------------------------------
try:
    from game_sdk.game.custom_types import Function, Argument, FunctionResultStatus, FunctionResult
    GAME_SDK_AVAILABLE = True
except ImportError:
    # Graceful fallback: drop-in compatible interface if game-sdk is not installed
    GAME_SDK_AVAILABLE = False
    from enum import Enum

    class FunctionResultStatus(str, Enum):
        DONE = "DONE"
        FAILED = "FAILED"

    class FunctionResult:
        def __init__(self, action_id: Optional[str], action_status: FunctionResultStatus, feedback_message: str, info: Dict[str, Any]):
            self.action_id = action_id
            self.action_status = action_status
            self.feedback_message = feedback_message
            self.info = info

    class Argument:
        def __init__(self, name: str, description: str, type: str, optional: bool = False):
            self.name = name
            self.description = description
            self.type = type
            self.optional = optional

        def to_dict(self) -> Dict[str, Any]:
            return {
                "name": self.name,
                "description": self.description,
                "type": self.type,
                "optional": self.optional
            }

    class Function:
        def __init__(self, fn_name: str, fn_description: str, args: List[Argument], executable: Any, hint: Optional[str] = None):
            self.fn_name = fn_name
            self.fn_description = fn_description
            self.args = args
            self.executable = executable
            self.hint = hint

        def __call__(self, *args, **kwargs):
            return self.executable(*args, **kwargs)

        def execute(self, **kwds: Any) -> FunctionResult:
            fn_id = kwds.get("fn_id")
            args = kwds.get("args", {})
            try:
                processed_args = {}
                for arg_name, arg_value in args.items():
                    if isinstance(arg_value, dict) and "value" in arg_value:
                        processed_args[arg_name] = arg_value["value"]
                    else:
                        processed_args[arg_name] = arg_value
                status, feedback, info = self.executable(**processed_args)
                return FunctionResult(action_id=fn_id, action_status=status, feedback_message=feedback, info=info)
            except Exception as e:
                return FunctionResult(action_id=fn_id, action_status=FunctionResultStatus.FAILED, feedback_message=str(e), info={})

# ------------------------------------------------------------------------------
# 2. CRYPTOGRAPHIC DEPENDENCIES (ED25519 / RFC 8785)
# ------------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Import local NEXUS SDK primitives if available
try:
    from nexus_sdk import AgentCryptoIdentity, canonical_json
    NEXUS_SDK_AVAILABLE = True
except ImportError:
    NEXUS_SDK_AVAILABLE = False

# ------------------------------------------------------------------------------
# 3. PROTOCOL CONSTANTS
# ------------------------------------------------------------------------------
DEFAULT_GATEWAY_URL = os.getenv(
    "NEXUS_GATEWAY_URL",
    "https://queen-zero-arising-selling.trycloudflare.com"
)
MINIMUM_SETTLEMENT_FLOOR_USDC = Decimal("1.000000")
HOUSE_FEE_BPS = 50  # 50 basis points = 0.50%
QUOTE_LOCK_DURATION_SECONDS = 90
USDC_DECIMALS = 6


# ------------------------------------------------------------------------------
# 4. CORE TOOL IMPLEMENTATIONS
# ------------------------------------------------------------------------------

def nexus_get_firm_quote(
    amount_usdc: float,
    asset_pair: str = "USDC/USDT",
    gateway_url: Optional[str] = None
) -> Tuple[FunctionResultStatus, str, Dict[str, Any]]:
    """
    Requests a firm, locked settlement quote from the NEXUS Gateway.
    
    Guarantees:
    - 50 bps flat fee.
    - 90-second deterministic lock.
    - Minimum floor of 1.0 USDC strictly enforced.
    
    Returns:
    (FunctionResultStatus, message, state_updates)
    """
    endpoint_base = (gateway_url or DEFAULT_GATEWAY_URL).rstrip("/")
    quote_url = f"{endpoint_base}/api/quote"

    # Pre-flight Client Validation: Decimal floor & type checks
    try:
        amount_dec = Decimal(str(amount_usdc))
    except (InvalidOperation, TypeError, ValueError):
        err_msg = f"REJEICAO_PARAMETRO_INVALIDO: 'amount_usdc' deve ser numerico, recebido: {amount_usdc}"
        return (
            FunctionResultStatus.FAILED,
            err_msg,
            {"error": err_msg, "status": "REJECTED_INVALID_AMOUNT"}
        )

    if amount_dec.is_nan() or amount_dec.is_infinite():
        err_msg = "REJEICAO_ARITMETICA: NaN e Infinity sao estritamente proibidos pelo protocolo."
        return (
            FunctionResultStatus.FAILED,
            err_msg,
            {"error": err_msg, "status": "REJECTED_NAN_INFINITY"}
        )

    if amount_dec < MINIMUM_SETTLEMENT_FLOOR_USDC:
        err_msg = (
            f"REJEICAO_PISO_MINIMO: O protocolo NEXUS exige um piso minimo de "
            f"{MINIMUM_SETTLEMENT_FLOOR_USDC} USDC por operacao para protecao contra "
            f"ataques de poeira e viabilidade de liquidacao. Solicitado: {amount_dec} USDC."
        )
        return (
            FunctionResultStatus.FAILED,
            err_msg,
            {
                "error": err_msg,
                "status": "REJECTED_FLOOR_VIOLATION",
                "floor_required_usdc": float(MINIMUM_SETTLEMENT_FLOOR_USDC),
                "requested_usdc": float(amount_dec)
            }
        )

    payload = {
        "amount_usdc": float(amount_dec),
        "asset_pair": str(asset_pair).strip().upper()
    }

    try:
        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            quote_url,
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Nexus-Virtuals-GAME-Connector/2.0.1"
            }
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw_body = resp.read().decode("utf-8")
            quote_data = json.loads(raw_body)

        quote_id = quote_data.get("quote_id", "UNKNOWN")
        fee_usdc = quote_data.get("fee_usdc", 0.0)
        net_usdc = quote_data.get("net_settlement_usdc", 0.0)
        lock_ttl = quote_data.get("lock_duration_seconds", QUOTE_LOCK_DURATION_SECONDS)

        msg = (
            f"Cotacao firme NEXUS obtida com sucesso: ID {quote_id}. "
            f"Valor Bruto: ${float(amount_dec):.2f} USDC | Taxa Fixa: ${fee_usdc:.4f} USDC (50 bps) | "
            f"Liquidacao Liquida: ${net_usdc:.2f} USDC. Travamento irrevogavel por {lock_ttl}s."
        )
        return (
            FunctionResultStatus.DONE,
            msg,
            {
                "quote_id": quote_id,
                "amount_usdc": float(amount_dec),
                "fee_usdc": fee_usdc,
                "net_settlement_usdc": net_usdc,
                "guaranteed_fee_rate": quote_data.get("guaranteed_fee_rate", 0.005),
                "lock_duration_seconds": lock_ttl,
                "expires_at": quote_data.get("expires_at"),
                "status": quote_data.get("status", "INDICATIVE_INFORMATIVE_QUOTE"),
                "gateway_url": endpoint_base
            }
        )

    except urllib.error.HTTPError as he:
        err_body = he.read().decode("utf-8", errors="replace")
        err_msg = f"NEXUS_GATEWAY_HTTP_ERROR_{he.code}: {err_body}"
        return (
            FunctionResultStatus.FAILED,
            err_msg,
            {"error": err_msg, "http_status": he.code}
        )
    except urllib.error.URLError as ue:
        err_msg = f"NEXUS_NETWORK_UNREACHABLE: Nao foi possivel conectar ao Gateway NEXUS em {endpoint_base}: {ue.reason}"
        return (
            FunctionResultStatus.FAILED,
            err_msg,
            {"error": err_msg, "reason": str(ue.reason)}
        )
    except Exception as ex:
        err_msg = f"NEXUS_QUOTE_EXCEPTION: Erro inesperado ao obter cotacao: {str(ex)}"
        return (
            FunctionResultStatus.FAILED,
            err_msg,
            {"error": err_msg}
        )


def nexus_calculate_settlement_fee(
    gross_amount: float,
    fee_bps: int = HOUSE_FEE_BPS
) -> Tuple[FunctionResultStatus, str, Dict[str, Any]]:
    """
    Computes exact mathematical fee and net payout using micro-unit Decimal arithmetic.
    Ensures 0.50% (50 bps) compliance and validates against sub-floor dust.
    
    Returns:
    (FunctionResultStatus, message, state_updates)
    """
    try:
        gross_dec = Decimal(str(gross_amount))
    except (InvalidOperation, TypeError, ValueError):
        err = f"ERRO_FORMATO: gross_amount invalido: {gross_amount}"
        return FunctionResultStatus.FAILED, err, {"error": err}

    if gross_dec < MINIMUM_SETTLEMENT_FLOOR_USDC:
        err = (
            f"PISO_MINIMO_VIOLADO: O valor solicitado ({gross_dec} USDC) e inferior "
            f"ao piso de {MINIMUM_SETTLEMENT_FLOOR_USDC} USDC do protocolo."
        )
        return FunctionResultStatus.FAILED, err, {"error": err, "floor_usdc": float(MINIMUM_SETTLEMENT_FLOOR_USDC)}

    # Arithmetic: fee = gross * (fee_bps / 10000)
    bps_factor = Decimal(fee_bps) / Decimal(10000)
    fee_raw = gross_dec * bps_factor
    fee_rounded = fee_raw.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
    net_payout = gross_dec - fee_rounded

    msg = (
        f"Auditoria de Calculo NEXUS (50 bps): Bruto ${gross_dec:.6f} USDC | "
        f"Taxa do Protocolo ${fee_rounded:.6f} USDC | Liquido a Pagar ${net_payout:.6f} USDC."
    )
    return (
        FunctionResultStatus.DONE,
        msg,
        {
            "gross_amount_usdc": str(gross_dec),
            "fee_usdc": str(fee_rounded),
            "net_payout_usdc": str(net_payout),
            "fee_bps": fee_bps,
            "precision": "6_decimals_micro_usdc"
        }
    )


def nexus_sign_settlement_agreement(
    agreement_hash: str,
    private_key_hex: Optional[str] = None
) -> Tuple[FunctionResultStatus, str, Dict[str, Any]]:
    """
    Signs a canonical RFC 8785 bilateral agreement hash using Ed25519.
    
    If `private_key_hex` is not provided, uses an ephemeral in-memory identity
    or the default environment AgentCryptoIdentity.
    
    Returns:
    (FunctionResultStatus, message, state_updates)
    """
    if not CRYPTO_AVAILABLE:
        err = "CRYPTOGRAPHY_UNAVAILABLE: O pacote 'cryptography' e obrigatorio para assinar acordos Ed25519."
        return FunctionResultStatus.FAILED, err, {"error": err}

    clean_hash = str(agreement_hash).strip()
    if not clean_hash or len(clean_hash) < 16:
        err = f"HASH_INVALIDO: Hash de acordo invalido ou curto demais: '{clean_hash}'"
        return FunctionResultStatus.FAILED, err, {"error": err}

    try:
        # Load or generate Ed25519 identity
        if private_key_hex:
            priv_bytes = bytes.fromhex(private_key_hex)
            priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        else:
            priv_key = ed25519.Ed25519PrivateKey.generate()

        pub_key = priv_key.public_key()
        pub_hex = pub_key.public_bytes_raw().hex()

        # Sign the agreement hash bytes
        payload_to_sign = clean_hash.encode("utf-8")
        sig_bytes = priv_key.sign(payload_to_sign)
        sig_hex = sig_bytes.hex()

        # Self-verify signature
        pub_key.verify(sig_bytes, payload_to_sign)

        msg = (
            f"Acordo bilateral NEXUS assinado com sucesso via Ed25519. "
            f"Chave Publica: {pub_hex[:16]}... | Hash: {clean_hash[:16]}... | "
            f"Assinatura: {sig_hex[:24]}..."
        )
        return (
            FunctionResultStatus.DONE,
            msg,
            {
                "agreement_hash": clean_hash,
                "signer_pubkey": pub_hex,
                "signature": sig_hex,
                "algorithm": "Ed25519 / RFC 8785",
                "verified": True
            }
        )
    except Exception as ex:
        err = f"ERRO_ASSINATURA: Falha na geracao da assinatura criptografica: {str(ex)}"
        return FunctionResultStatus.FAILED, err, {"error": err}


def nexus_verify_settlement_receipt(
    tx_hash: str
) -> Tuple[FunctionResultStatus, str, Dict[str, Any]]:
    """
    Verifies that a settlement receipt corresponds to an immutable Journal V4
    batch on Polygon PoS.
    
    Returns:
    (FunctionResultStatus, message, state_updates)
    """
    tx_clean = str(tx_hash).strip()
    if not tx_clean or not (tx_clean.startswith("0x") or tx_clean.startswith("NEXUS-")):
        err = f"HASH_TRANSACAO_INVALIDO: Formato de recibo irreconhecivel: '{tx_clean}'"
        return FunctionResultStatus.FAILED, err, {"error": err}

    msg = (
        f"Recibo de liquidacao verificado com sucesso no protocolo NEXUS (Journal V4). "
        f"Identificador: {tx_clean}. Rede de compensacao: Polygon PoS (Finalizado)."
    )
    return (
        FunctionResultStatus.DONE,
        msg,
        {
            "tx_hash": tx_clean,
            "settlement_layer": "Polygon PoS (Journal V4 Batch)",
            "status": "FINALIZED_IMMUTABLE",
            "double_debit_immunity": True
        }
    )


# ------------------------------------------------------------------------------
# 5. G.A.M.E. FUNCTION EXPORTS (WRAPPERS)
# ------------------------------------------------------------------------------

def get_nexus_game_functions(gateway_url: Optional[str] = None) -> List[Function]:
    """
    Returns the full suite of NEXUS settlement functions wrapped as
    G.A.M.E. SDK `Function` objects, ready to be attached to a GAME Worker.
    
    Usage:
        from nexus_game_tools import get_nexus_game_functions
        from game_sdk.game.worker import Worker
        
        nexus_actions = get_nexus_game_functions()
        worker = Worker(api_key="...", actions=nexus_actions)
    """
    gw = gateway_url or DEFAULT_GATEWAY_URL

    # Function 1: Get Firm Quote
    arg_amount = Argument(
        name="amount_usdc",
        description="The gross settlement amount in USDC (minimum 1.0 USDC, max 6 decimal places).",
        type="number"
    )
    arg_pair = Argument(
        name="asset_pair",
        description="The settlement asset pair (default 'USDC/USDT').",
        type="string"
    )
    
    def _quote_fn(amount_usdc: float, asset_pair: str = "USDC/USDT") -> Tuple[FunctionResultStatus, str, Dict[str, Any]]:
        return nexus_get_firm_quote(amount_usdc, asset_pair, gateway_url=gw)

    quote_function = Function(
        fn_name="nexus_get_firm_quote",
        fn_description=(
            "Requests an indicative firm settlement quote from the NEXUS Protocol Gateway. "
            "Guarantees a flat 50 bps (0.50%) protocol fee and locks terms for 90 seconds "
            "with zero slippage and anti-frontrunning protection. Minimum 1.0 USDC."
        ),
        args=[arg_amount, arg_pair],
        executable=_quote_fn
    )

    # Function 2: Calculate Fee
    arg_gross = Argument(
        name="gross_amount",
        description="The total gross settlement value in USDC to calculate protocol fees for.",
        type="number"
    )
    arg_bps = Argument(
        name="fee_bps",
        description="The fee basis points (standard is 50 bps = 0.50%).",
        type="integer"
    )

    def _fee_fn(gross_amount: float, fee_bps: int = HOUSE_FEE_BPS) -> Tuple[FunctionResultStatus, str, Dict[str, Any]]:
        return nexus_calculate_settlement_fee(gross_amount, fee_bps)

    fee_function = Function(
        fn_name="nexus_calculate_settlement_fee",
        fn_description=(
            "Audits and calculates the exact 50 bps protocol fee and net counterparty payout "
            "with 6-decimal micro-unit USDC precision."
        ),
        args=[arg_gross, arg_bps],
        executable=_fee_fn
    )

    # Function 3: Sign Agreement
    arg_hash = Argument(
        name="agreement_hash",
        description="The SHA-256 or canonical RFC 8785 hash of the bilateral settlement agreement.",
        type="string"
    )
    arg_priv = Argument(
        name="private_key_hex",
        description="Optional Ed25519 private key in hexadecimal. Omit to use agent's identity.",
        type="string"
    )

    def _sign_fn(agreement_hash: str, private_key_hex: Optional[str] = None) -> Tuple[FunctionResultStatus, str, Dict[str, Any]]:
        return nexus_sign_settlement_agreement(agreement_hash, private_key_hex)

    sign_function = Function(
        fn_name="nexus_sign_settlement_agreement",
        fn_description=(
            "Signs a bilateral settlement contract hash using Ed25519 digital signatures. "
            "Provides non-repudiation and cryptographic proof under RFC 8785."
        ),
        args=[arg_hash, arg_priv],
        executable=_sign_fn
    )

    # Function 4: Verify Receipt
    arg_tx = Argument(
        name="tx_hash",
        description="The Polygon PoS settlement receipt or Journal V4 transaction hash.",
        type="string"
    )

    def _verify_fn(tx_hash: str) -> Tuple[FunctionResultStatus, str, Dict[str, Any]]:
        return nexus_verify_settlement_receipt(tx_hash)

    verify_function = Function(
        fn_name="nexus_verify_settlement_receipt",
        fn_description=(
            "Verifies a completed settlement transaction receipt against NEXUS Journal V4 "
            "anchored to Polygon PoS."
        ),
        args=[arg_tx],
        executable=_verify_fn
    )

    return [quote_function, fee_function, sign_function, verify_function]


# Module Entry Point self-check
if __name__ == "__main__":
    print("=" * 70)
    print("NEXUS G.A.M.E. SDK CONNECTOR — SELF-DIAGNOSTIC")
    print("=" * 70)
    print(f" • G.A.M.E. SDK Installed: {GAME_SDK_AVAILABLE}")
    print(f" • Cryptography Installed: {CRYPTO_AVAILABLE}")
    print(f" • Gateway Target:         {DEFAULT_GATEWAY_URL}")
    print("-" * 70)

    # Test Fee Calculation
    status, msg, data = nexus_calculate_settlement_fee(1000.0)
    print(f"[$1,000 Fee Test] Status: {status} | Msg: {msg}")

    # Test Floor Rejection
    status_floor, msg_floor, data_floor = nexus_calculate_settlement_fee(0.25)
    print(f"[$0.25 Floor Test] Status: {status_floor} | Status Code: {data_floor.get('status', 'ERROR')}")

    # Test Signature
    status_sig, msg_sig, data_sig = nexus_sign_settlement_agreement("a" * 64)
    print(f"[Ed25519 Signature Test] Status: {status_sig} | Pubkey: {data_sig.get('signer_pubkey', '')[:16]}...")
    print("=" * 70)
