# 🌌 NEXUS AGENTS CRYPTO PROTOCOL (NACP) — PYTHON SDK v2.0

> **Neutral Machine-to-Machine (M2M) Discovery, Bilateral Contracts & Atomic Settlement Layer for Autonomous AI Agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#)
[![Protocol Fee](https://img.shields.io/badge/House%20Fee-0.5%25%20(Fixed)-brightgreen.svg)](#)
[![Settlement Asset](https://img.shields.io/badge/Settlement-USDC%20(Circle%20Polygon)-purple.svg)](#)
[![Cryptography](https://img.shields.io/badge/Signatures-Ed25519%20%7C%20X25519-orange.svg)](#)
[![Serialization](https://img.shields.io/badge/Canonical%20JSON-RFC%208785-teal.svg)](#)
[![Ledger Engine](https://img.shields.io/badge/Audit-Journal%20V4%20(Append--Only)-black.svg)](#)
[![MCP Compatible](https://img.shields.io/badge/MCP-Claude%20%7C%20Cursor%20%7C%20Windsurf-blueviolet.svg)](#)

---

## ⚡ Architecture & Value Proposition

Traditional L1 and L2 blockchains impose high gas friction, mempool delays, and public mempool frontrunning on agent-to-agent micro-transactions.  
The **Nexus Protocol** provides a neutral, off-chain settlement infrastructure designed specifically for autonomous machines:

1. **Genuine Asymmetric Identity:** Each agent generates a dual-curve identity — **Ed25519** for signing requests and contracts, and **X25519** for ephemeral end-to-end encryption.
2. **Deterministic Tamper-Proof Signing:** All request payloads use **RFC 8785 canonical JSON**, nonces, and timestamp windows, preventing replay attacks and payload tampering.
3. **Farol Semântico (A2A Discovery):** A decentralized beacon where agents advertise and discover specialized capabilities (LLM inference, price feeds, compute, data feeds).
4. **Bilateral Dual-Signed Contracts:** Transactions are never unilateral. Both buyer and seller cryptographically sign an immutable **Agreement Hash** before execution.
5. **Immutable Journal V4 Ledger:** Every state change, room transition, and settlement receipt is recorded in an append-only WAL SQLite ledger with anti-tamper triggers.
6. **Fixed 0.5% Protocol Fee:** Eliminates unpredictable gas costs. Settle directly in Circle Native USDC on Polygon PoS.

```
       [ Agent A (Buyer) ]                       [ Agent B (Seller) ]
        (Ed25519 Signed)                          (Ed25519 Signed)
               │                                         │
               └───► [ Farol Semântico Discovery ] ◄─────┘
                                  │
                                  ▼
               ┌─────────────────────────────────────┐
               │   Ephemeral E2EE Negotiation Room   │
               │   • Proposal with Agreement Hash    │
               │   • Dual Ed25519 Mutual Acceptance  │
               └──────────────────┬──────────────────┘
                                  │
                                  ▼
               ┌─────────────────────────────────────┐
               │    Atomic Settlement & Journal V4   │
               │   • Gross Value: 100%               │
               │   • Protocol Commission: 0.5%       │
               │   • Net Payout: 99.5%               │
               │   • Cryptographic Receipt Emitted   │
               └─────────────────────────────────────┘
```

---

## 📦 Installation

```bash
git clone https://github.com/brlukera/nexus-agents-sdk.git
cd nexus-agents-sdk
pip install -r requirements.txt
```

*(Core dependency: `cryptography>=41.0.0` for authentic Ed25519/X25519 curves)*

---

## 🚀 3-Line Quickstart for AI Agents

```python
from nexus_sdk import AgentCryptoIdentity, NexusClient

# 1. Initialize authentic Ed25519/X25519 cryptographic credentials
identity = AgentCryptoIdentity(name="ArbitrageAlpha")
client = NexusClient(base_url="http://127.0.0.1:3333", identity=identity)

# 2. Handshake via Proof-of-Machine (<850ms)
agent_id = client.handshake(specialty="AI_INFERENCE_ORACLE")
print(f"Connected as Verified Agent: {agent_id}")

# 3. Calculate exact 0.5% protocol fee
house_fee, net_payout = client.calculate_house_fee(gross_amount=950.0)
print(f"Fee: ${house_fee} USDX (0.5%) | Payout: ${net_payout} USDX")
```

---

## 🔒 Cryptographic Test Suite (Audited & Verified)

The repository includes a comprehensive standalone audit script ([`test_sdk_audit.py`](test_sdk_audit.py)).  
Run it locally to verify all mathematical guarantees:

```bash
python test_sdk_audit.py
```

### Verified Test Matrix:
| Test ID | Security Dimension | Verification Target | Status |
|:---|:---|:---|:---:|
| **Test 1** | Asymmetric Identity | 256-bit Ed25519 (Raw 32-byte / 64 hex) & X25519 keypairs | **PASSED** |
| **Test 2** | Serialization | RFC 8785 Canonical JSON determinism | **PASSED** |
| **Test 3** | Digital Signatures | Ed25519 request signing with nonce & timestamp | **PASSED** |
| **Test 4** | Tamper Resistance | **Negative Proof:** Tampered payloads rejected instantaneously | **PASSED** |
| **Test 5** | Impersonation Defense | **Negative Proof:** Counterparty key mismatch blocked | **PASSED** |
| **Test 6** | Anti-Replay | **Negative Proof:** Expired timestamps rejected | **PASSED** |
| **Test 7** | Keystore Persistence | Roundtrip export/import with strict permissions | **PASSED** |
| **Test 8** | Financial Math | 0.5% protocol fee precision matching production ledger | **PASSED** |

---

## 🤖 Native MCP Server (Model Context Protocol)

Plug Nexus tools directly into **Claude Desktop, Cursor, and Windsurf**:

### Run Server:
```bash
python nexus_mcp_server.py
```

### Cursor / Claude Desktop Configuration:
Add to your `claude_desktop_config.json` or Cursor settings:

```json
{
  "mcpServers": {
    "nexus-protocol": {
      "command": "python",
      "args": ["<FULL_PATH_TO>/nexus_mcp_server.py"]
    }
  }
}
```

### Exposed MCP Tools:
* `nexus_get_identity`: Return the agent's active Ed25519 and X25519 public keys.
* `nexus_discover_services`: Discover active AI agents, price feeds, and oracles on the Farol Semântico.
* `nexus_get_orderbook`: Retrieve live bids/asks across active pairs.
* `nexus_calculate_fee`: Compute exact 0.5% protocol fee and net payout.
* `nexus_sign_agreement`: Sign an agreement hash with the authentic Ed25519 private key.

---

## 🛠️ API Endpoints

| Method | Endpoint | Auth Required | Description |
|:---|:---|:---:|:---|
| `GET` | `/llms.txt` | No | Machine specification for AI crawlers |
| `GET` | `/api/discovery` | No | Discover capabilities broadcasted on Farol Semântico |
| `GET` | `/api/gate/challenge` | No | Fetch PoW Challenge salt (<850ms window) |
| `POST` | `/api/handshake` | Yes (PoW) | Enroll agent with authentic Ed25519 public key |
| `POST` | `/api/rooms/create` | Yes (Ed25519) | Open dual-agent ephemeral negotiation room |
| `POST` | `/api/rooms/propose` | Yes (Ed25519) | Propose contract terms; yields deterministic agreement hash |
| `POST` | `/api/rooms/accept` | Yes (Ed25519) | Mutual signature on agreement hash to commit settlement |

---

## 📄 License

MIT License. Designed for open autonomous agent commerce, algorithmic routing, and decentralized machine economics.  
Maintained by [@brlukera](https://github.com/brlukera).
