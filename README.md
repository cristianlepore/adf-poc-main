# Agentic Delegation Framework (ADF)

**A capability-based security layer for multi-hop AI agent delegation.**

> *"AgentBeats evaluates what agents do. ADF ensures they do it within their delegated scope."*

---

## Motivation

As AI agents become more capable, they increasingly delegate tasks to other agents across organizational boundaries. A user asks ChatGPT to book a trip → ChatGPT delegates to a Lufthansa agent → Lufthansa delegates payment to Stripe.

The problem: **existing systems have no mechanism to enforce and verify that each agent in the chain operates strictly within its assigned permissions.** An agent that receives limited access can silently pass broader privileges downstream, with no traceability back to the original user.

ADF addresses this gap with **cryptographically verifiable, attenuating capabilities**.

---

## Core Concepts

### Capability
A signed permission token specifying:
- **Who** is authorized (`subject`)
- **What** they can do (`permissions`)
- **For how long** (`valid_from`, `valid_until`)
- **Who authorized them** (`issuer`, `parent_id`)

### Attenuation
When an agent delegates to a sub-agent, it creates a *child capability* with **equal or fewer permissions**. A child can never have more permissions than its parent.

```
Alice (budget: $2000)
  └─ ChatGPT (budget: $1600)
       └─ Lufthansa (budget: $800)
            └─ Stripe (budget: $750, one-time, no retention)
```

### Execution Proof
Every agent action produces a **tamper-evident proof** (SHA-256 hash). The GreenAgent collects all proofs and verifies the full chain end-to-end.

### Registry
A central store that tracks all issued capabilities, supports **cascade revocation**, and enables chain reconstruction and verification.

---

## Integration with AgentBeats

ADF extends AgentBeats with **delegation-aware evaluation**:

| AgentBeats (baseline)        | AgentBeats + ADF                          |
|------------------------------|-------------------------------------------|
| Green agent evaluates performance | Green agent evaluates performance **and delegation correctness** |
| Purple agent is a black box internally | Full delegation chain is transparent and verifiable |
| A2A protocol for communication | A2A + ADF capability tokens for authorization |
| No visibility into sub-agent permissions | Every hop is cryptographically traceable |

---

## Project Structure

```
adf/
├── capability.py      # Capability dataclass — attenuation, renewal, signing
├── proof.py           # ExecutionProof and ProofChain
├── registry.py        # CapabilityRegistry — revocation, chain verification
└── agents/
    ├── base.py        # BaseAgent — validation, execute, delegate
    ├── green.py       # GreenAgent — evaluator and chain verifier
    └── purple.py      # PurpleAgent — competing agent with delegation
demo.py                # 4 scenarios: happy path, renewal, violation, revocation
```

---

## Quick Start

**No dependencies required** — standard Python 3.10+ only.

```bash
python demo.py
```

---

## Demo Scenarios

| Scenario | What it demonstrates |
|----------|----------------------|
| Happy path | Full Alice → ChatGPT → Lufthansa → Stripe chain with verification |
| Renewal | Short-lived capability extended within allowed renewal count |
| Violation | Stripe attempts privilege escalation — blocked by ADF |

---

## Author
*Cristian Lepore*  

---

## Status

Proof-of-concept implementation.
