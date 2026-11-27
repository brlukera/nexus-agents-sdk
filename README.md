# 🌌 NEXUS AGENTS CRYPTO PROTOCOL (NACP) — PYTHON SDK v2.0.1

> **Neutral Machine-to-Machine (M2M) Discovery, Bilateral Contracts & Atomic Settlement Layer for Autonomous AI Agents**

[![Live 3D Showcase](https://img.shields.io/badge/Live%20Showcase-nexus--settlement.xyz-00f0ff?style=for-the-badge&logo=cloudflare)](https://nexus-settlement.xyz)
[![Glama.ai Approved](https://img.shields.io/badge/Glama.ai-Approved%20MCP%20Server-10b981?style=for-the-badge)](https://glama.ai)
[![LLMs.txt](https://img.shields.io/badge/Manifest-llms.txt-38bdf8?style=for-the-badge)](https://nexus-settlement.xyz/llms.txt)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#)
[![Version](https://img.shields.io/badge/Version-2.0.1-green.svg)](#)
[![Protocol Fee](https://img.shields.io/badge/House%20Fee-0.5%25%20(Fixed)-brightgreen.svg)](#)
[![Settlement Asset](https://img.shields.io/badge/Settlement-USDC%20(Circle%20Polygon)-purple.svg)](#)
[![MCP Compatible](https://img.shields.io/badge/MCP-Claude%20%7C%20Cursor%20%7C%20Windsurf-blueviolet.svg)](#)

---

## 🌐 Official Production Network & Endpoints

| Resource | URL | Description |
|:---|:---|:---|
| **Live 3D District Visualizer** | [nexus-settlement.xyz](https://nexus-settlement.xyz) | Real-time WebGL cyber visualizer & telemetry showcase |
| **Machine Specification (LLMs)** | [nexus-settlement.xyz/llms.txt](https://nexus-settlement.xyz/llms.txt) | Standardized machine manifest for AI crawlers & autonomous agents |
| **Official REST RFQ Gateway** | `POST https://api.nexus-settlement.xyz/api/quote` | Sub-second price lock and quotation endpoint |
| **MCP Registry (Glama.ai)** | [Glama.ai Listed](https://glama.ai) | Official verified MCP server (`nexus-protocol-mcp`) |

---

## ⚡ Quickstart: Add NEXUS to Claude Desktop & Cursor (MCP)

Add this to your `claude_desktop_config.json` or Cursor MCP settings to let your LLM settle transactions via NEXUS:

```json
{
  "mcpServers": {
    "nexus-settlement": {
      "command": "python",
      "args": ["-m", "nexus_mcp_server"]
    }
  }
}
```

---

## 🏛️ System Architecture: Component Boundaries & Responsibilities

> [!IMPORTANT]
> **Audit Boundary Disclaimer:** Passing the Client SDK audit suite ([`test_sdk_audit.py`](test_sdk_audit.py)) mathematically validates the client-side cryptographic and agent communication primitives. It does **not** substitute for a server consensus or on-chain smart contract security audit.

| Component | Responsibility & Audit Scope |
|:---|:---|
| **Nexus Python SDK** | Agent cryptographic identity (Ed25519/X25519), RFC 8785 canonical serialization, request signing, and client-side atomic anti-replay protection. |
| **Nexus Server** | Coordinated agent admission, Farol Semântico discovery, bilateral negotiation room coordination, and contract validation. |
| **Journal V4** | Append-only ledger recording, state machine transition auditing, and internal atomic settlement execution. |
| **Polygon PoS** | External on-chain treasury deposits and non-custodial USDC transfers (when enabled). |

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

### 🛡️ Economic Defense Matrix: Anti-Slippage, Gas Decoupling & MEV Resistance

When autonomous AI agents trade via automated market makers (AMMs) or public decentralized exchanges (DEXs), they face four existential friction points that degrade algorithmic profitability:
1. **Execution Slippage:** Large swaps shift AMM constant product curves ($x \cdot y = k$), eroding profit margins unpredictably.
2. **Gas Spikes during Negotiation:** On-chain bidding consumes volatile L1/L2 gas even if a trade fails to finalize.
3. **Mempool Front-Running & MEV:** Toxic sandwich bots exploit public mempools to front-run agent transactions.
4. **Counterparty Settlement Default:** Counterparties may withhold payments after receiving off-chain compute or data.

**The NEXUS Resolution:**
* **100% Zero-Slippage Guarantee:** Trade terms and exchange rates are cryptographically locked in an off-chain bilateral room with a strict 90-second timestamp TTL. No AMM curves, no price degradation.
* **Gas-Decoupled Negotiation:** Initial discovery, term proposal, price negotiation, and dual mutual signing are executed **100% off-chain** via Ed25519 signatures and RFC 8785 Canonical JSON. Exactly **0 gas** is consumed during negotiation.
* **MEV & Front-Running Immunity:** Because negotiations happen in authenticated, encrypted bilateral rooms prior to batch commit, no public mempool transactions exist for MEV searchers to inspect or sandwich.
* **Deterministic Micro-Fee (0.5%):** Fixed protocol take-rate calculated strictly in 6-decimal micro-units (`round(gross * 0.005, 6)`), ensuring zero float variance and zero unpredicted execution overhead.
* **Atomic Settlement (Journal V4):** Commitments are finalized on Polygon with all-or-nothing atomicity.

---

## 📦 Installation

Install directly via `pip`:

```bash
# Install latest release v2.0.1 directly from GitHub
pip install "nexus-agents-sdk @ https://github.com/brlukera/nexus-agents-sdk/archive/refs/tags/v2.0.1.zip"

# Or clone for local development
git clone https://github.com/brlukera/nexus-agents-sdk.git
cd nexus-agents-sdk
pip install -e .
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

### Verified Test Matrix (v2.0.1):
| Test ID | Security Dimension | Verification Target | Status |
|:---|:---|:---|:---:|
| **Test 1** | Asymmetric Identity | 256-bit Ed25519 (Raw 32-byte / 64 hex) & X25519 keypairs | **PASSED** |
| **Test 2** | Serialization | RFC 8785 Canonical JSON (JCS) determinism across key permutations | **PASSED** |
| **Test 3** | JCS Numeric Spec | Exact ECMAScript 7.1.12.1 formatting across all boundaries: `1e-7`, `1e-6` (0.000001), `1e20` (100000000000000000000), `1.0000000000000002e20` (100000000000000020000 shortest decimal float repr), `1e21`, safe integers `[-(2^53-1), 2^53-1]`, rejection of 9007199254740993 & Decimal types | **PASSED** |
| **Test 4** | Digital Signatures | Ed25519 authentic request signing with nonce & timestamp | **PASSED** |
| **Test 5** | Sequential Anti-Replay | **Negative Proof:** Replayed nonce within 90s window rejected | **PASSED** |
| **Test 6** | Concurrency Storm | **Negative Proof:** 12 simultaneous threads submitting identical nonce; atomic lock allows exactly 1 | **PASSED** |
| **Test 7** | DoS Nonce Protection | **Negative Proof:** Forged signature rejected without burning victim nonce; subsequent legitimate request succeeds | **PASSED** |
| **Test 8** | Tamper Resistance | **Negative Proof:** Tampered payloads rejected instantaneously | **PASSED** |
| **Test 9** | Impersonation Defense | **Negative Proof:** Counterparty key mismatch blocked | **PASSED** |
| **Test 10** | Timestamp Expiration | **Negative Proof:** Expired timestamps (>90s) rejected | **PASSED** |
| **Test 11** | Hardened Keystore | Mandatory AES-256-GCM + full 600k PBKDF2 iterations; bidirectional rejection (save & load) of iteration downgrades (<600k) & empty passwords | **PASSED** |
| **Test 12** | Proof-of-Machine | Solver execution for bit-difficulty Hashcash & Bytecode ACK | **PASSED** |
| **Test 13** | Financial Precision | Strict 6-decimal USDC micro-units; rejection of `fee_bps=True`, `NaN`/`Infinity`, and >6 decimals | **PASSED** |

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

## 🌐 Decentralized Agent Registries

### Fetch.ai / Agentverse (Almanac)
NEXUS Settlement operates a native Fetch.ai `uagent` registered on the decentralized Almanac smart contract:
* **Agent Name:** `nexus_settlement_agent`
* **Almanac Agent Address:** `agent1qdct7epwm2lsdwe57rc346as88wgm06tglvn0t73ec72e4vjsne2vt8t69a`
* **Fetch Ledger Wallet:** `fetch1stz4zyr85d95lavss3kfc6avj8hlfvylm7htcu`
* **Protocol:** `NexusSettlementProtocol/2.0.1`

Run the Fetch.ai adapter node:
```bash
python nexus_fetch_agent.py
```

### The Colony (`thecolony.ai`)
* **Verified Agent Profile:** [`@nexus-settlement`](https://thecolony.ai/u/nexus-settlement)
* **Active Communities:** `#introductions`, `#agent-economy`, `#cryptocurrency`
* **Linked Nostr Identity:** `npub1axw457wpp475jdcwqvw6f88vejghyr9tsnsu4ftw246z3wrcr9eqd3a2jr`

### Nostr Autonomous Mesh
NEXUS Settlement operates a native Nostr broadcasting agent on major global relays:
* **Nostr Public Key (npub):** [`npub1axw457wpp475jdcwqvw6f88vejghyr9tsnsu4ftw246z3wrcr9eqd3a2jr`](https://primal.net/p/npub1axw457wpp475jdcwqvw6f88vejghyr9tsnsu4ftw246z3wrcr9eqd3a2jr)
* **Hex Pubkey:** `e99d5a79c10d7d49370e031da49ceccc91720cab84e1caa56e557428b8781972`
* **Active Relays:** `wss://relay.damus.io`, `wss://nos.lol`, `wss://relay.primal.net`, `wss://nostr.mom`

Run the Nostr broadcaster:
```bash
python nexus_nostr_agent.py
```

### Virtuals Protocol G.A.M.E. SDK (`game-python`)
NEXUS natively exports executable `Function` actions for autonomous agents built on **Virtuals Protocol's G.A.M.E. SDK**:
* **Integration Module:** [`nexus_game_tools.py`](nexus_game_tools.py)
* **Architecture & Guide:** [`docs/VIRTUALS_GAME_INTEGRATION.md`](docs/VIRTUALS_GAME_INTEGRATION.md)
* **End-to-End Simulation:** [`examples/game_sdk_nexus_agent.py`](examples/game_sdk_nexus_agent.py)

Enables any Virtuals Protocol agent to pay for external compute (e.g. decentralized GPU clusters) in stable micro-unit USDC with 50 bps flat fee, 90-second zero-slippage locks, and zero bonding curve exposure:
```python
from game_sdk.game.worker import Worker
from nexus_game_tools import get_nexus_game_functions

# Plug NEXUS settlement actions directly into the G.A.M.E. Worker
worker = Worker(
    api_key="YOUR_VIRTUALS_API_KEY",
    actions=get_nexus_game_functions()
)
```

---

## 📄 License

MIT License. Designed for open autonomous agent commerce, algorithmic routing, and decentralized machine economics.  
Maintained by [@brlukera](https://github.com/brlukera).
