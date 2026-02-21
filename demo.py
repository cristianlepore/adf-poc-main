"""
demo.py
=======
ADF Proof-of-Concept Demo
--------------------------
Scenario: Alice asks ChatGPT to book a flight to Tokyo.
ChatGPT delegates to Lufthansa. Lufthansa delegates payment to Stripe.

Demonstrates:
1. Root capability creation (FIDO2-authenticated in production)
2. Multi-hop delegation with automatic capability attenuation
3. Cryptographic proof collection across the full agent chain
4. End-to-end chain verification by the GreenAgent
5. Capability renewal
6. Violation detection (privilege escalation attempt)
7. Revocation cascade
"""

import time

from adf.capability import create_root_capability
from adf.registry import CapabilityRegistry
from adf.agents.base import BaseAgent
from adf.agents.green import GreenAgent
from adf.agents.purple import PurpleAgent


def separator(title: str = "") -> None:
    print("\n" + "─" * 60)
    if title:
        print(f"  {title}")
        print("─" * 60)


# ══════════════════════════════════════════════════════════════
# SCENARIO 1: Happy path — full delegation chain
# ══════════════════════════════════════════════════════════════

def demo_happy_path():
    separator("SCENARIO 1: Happy path — Alice → ChatGPT → Lufthansa → Stripe")

    registry = CapabilityRegistry()

    # Alice creates the root capability after FIDO2 authentication
    root_cap = create_root_capability(
        issuer="alice",
        subject="chatgpt_agent",
        permissions={
            "action": "travel_booking",
            "budget_max": 2000,
            "data_access": "calendar_only",
            "validity_hours": 24,
        },
        duration_seconds=86400,  # 24 hours
        max_renewals=1,
    )
    print(f"\n  Alice's root capability:\n  {root_cap}")

    # Build the agent chain
    stripe_agent    = BaseAgent("stripe_agent", registry)
    lufthansa_agent = PurpleAgent("lufthansa_agent", registry, sub_agents=[stripe_agent])
    chatgpt_agent   = PurpleAgent("chatgpt_agent", registry, sub_agents=[lufthansa_agent])
    green_agent     = GreenAgent("green_evaluator", registry)

    # GreenAgent runs the evaluation
    result = green_agent.evaluate(
        purple_agent=chatgpt_agent,
        task="Book a round-trip flight to Tokyo, budget $2000",
        root_capability=root_cap,
    )

    print(f"\n  Registry state: {registry}")
    return result


# ══════════════════════════════════════════════════════════════
# SCENARIO 2: Capability renewal
# ══════════════════════════════════════════════════════════════

def demo_renewal():
    separator("SCENARIO 2: Capability renewal")

    registry = CapabilityRegistry()

    # Short-lived capability (5 seconds) with 2 allowed renewals
    cap = create_root_capability(
        issuer="alice",
        subject="chatgpt_agent",
        permissions={"action": "research", "budget_max": 500},
        duration_seconds=5,
        max_renewals=2,
    )
    registry.register(cap)

    print(f"\n  Initial capability: {cap}")
    print(f"  Can renew: {cap.can_renew()} (renewals used: {cap.renewal_count}/{cap.max_renewals})")

    # First renewal: +60 seconds
    cap.renew(additional_seconds=60)
    print(f"\n  After 1st renewal: {cap}")
    print(f"  Can renew: {cap.can_renew()} (renewals used: {cap.renewal_count}/{cap.max_renewals})")

    # Second renewal: +60 seconds
    cap.renew(additional_seconds=60)
    print(f"\n  After 2nd renewal: {cap}")
    print(f"  Can renew: {cap.can_renew()} (renewals used: {cap.renewal_count}/{cap.max_renewals})")

    # Third renewal: should fail
    print(f"\n  Attempting 3rd renewal (should fail)...")
    try:
        cap.renew(additional_seconds=60)
    except Exception as e:
        print(f"  ❌ Blocked: {e}")


# ══════════════════════════════════════════════════════════════
# SCENARIO 3: Privilege escalation attempt
# ══════════════════════════════════════════════════════════════

def demo_violation():
    separator("SCENARIO 3: Privilege escalation — Stripe tries to exceed its budget")

    registry = CapabilityRegistry()

    root_cap = create_root_capability(
        issuer="alice",
        subject="chatgpt_agent",
        permissions={"action": "travel_booking", "budget_max": 2000},
        duration_seconds=3600,
    )
    registry.register(root_cap)

    # Attenuate for Lufthansa (budget: 800)
    lufthansa_cap = root_cap.attenuate(
        new_subject="lufthansa_agent",
        reduced_permissions={"action": "book_flight", "budget_max": 800},
    )
    registry.register(lufthansa_cap)
    print(f"\n  Lufthansa capability: {lufthansa_cap}")

    # Stripe tries to attenuate with budget: 9999 (higher than Lufthansa's 800)
    print(f"\n  Stripe attempting privilege escalation (budget 9999 > 800)...")
    try:
        stripe_cap = lufthansa_cap.attenuate(
            new_subject="stripe_agent",
            reduced_permissions={"action": "charge_card", "budget_max": 9999},
        )
    except Exception as e:
        print(f"  ❌ Escalation blocked: {e}")


# ══════════════════════════════════════════════════════════════
# SCENARIO 4: Revocation cascade
# ══════════════════════════════════════════════════════════════

def demo_revocation():
    separator("SCENARIO 4: Revocation cascade — Alice revokes ChatGPT mid-flight")

    registry = CapabilityRegistry()

    root_cap = create_root_capability(
        issuer="alice",
        subject="chatgpt_agent",
        permissions={"action": "travel_booking", "budget_max": 2000},
        duration_seconds=3600,
    )
    registry.register(root_cap)

    lufthansa_cap = root_cap.attenuate("lufthansa_agent", {"action": "book_flight", "budget_max": 800})
    registry.register(lufthansa_cap)

    stripe_cap = lufthansa_cap.attenuate("stripe_agent", {"action": "charge_card", "budget_max": 750})
    registry.register(stripe_cap)

    print(f"\n  Registry before revocation: {registry}")
    print(f"  Stripe capability valid: {registry.is_fully_valid(stripe_cap)}")

    # Alice revokes the root capability (e.g. trip cancelled)
    print(f"\n  Alice revokes root capability (cascade)...")
    revoked_count = registry.revoke(root_cap.capability_id, reason="Trip cancelled by Alice.")
    print(f"  Revoked {revoked_count} capability/capabilities in cascade.")

    print(f"\n  Registry after revocation: {registry}")
    print(f"  Root revoked    : {registry.is_revoked(root_cap.capability_id)}")
    print(f"  Lufthansa revoked: {registry.is_revoked(lufthansa_cap.capability_id)}")
    print(f"  Stripe revoked  : {registry.is_revoked(stripe_cap.capability_id)}")
    print(f"  Stripe capability now valid: {registry.is_fully_valid(stripe_cap)}")


# ══════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "█" * 60)
    print("  Agentic Delegation Framework (ADF) — Demo")
    print("  Proof-of-Concept for AgentBeats integration")
    print("█" * 60)

    demo_happy_path()
    demo_renewal()
    demo_violation()
    demo_revocation()

    print("\n" + "█" * 60)
    print("  All scenarios complete.")
    print("█" * 60)
