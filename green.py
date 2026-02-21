"""
adf/agents/green.py
===================
Green (evaluator) agent — the benchmark and judge.

The GreenAgent orchestrates the entire evaluation lifecycle:
1. Issues a root capability to the purple agent.
2. Assigns the task.
3. Collects all ExecutionProofs from the delegation chain.
4. Verifies the chain end-to-end (performance + delegation correctness).

This makes AgentBeats not just a performance evaluator, but also a
delegation-aware security validator — the core contribution of ADF.
"""

import json
import time

from adf.capability import Capability
from adf.proof import ExecutionProof, ProofChain
from adf.registry import CapabilityRegistry
from adf.agents.base import BaseAgent
from adf.agents.purple import PurpleAgent


class EvaluationResult:
    """
    Structured result of a GreenAgent evaluation run.

    Contains:
    - Whether the delegation chain was valid end-to-end.
    - A list of any delegation violations detected.
    - All collected execution proofs.
    - A performance score (placeholder — extend with domain-specific metrics).
    """

    def __init__(
        self,
        task: str,
        chain_valid: bool,
        violations: list[str],
        proof_chain: ProofChain,
        agents_involved: list[str],
        duration_seconds: float,
    ):
        self.task = task
        self.chain_valid = chain_valid
        self.violations = violations
        self.proof_chain = proof_chain
        self.agents_involved = agents_involved
        self.duration_seconds = duration_seconds
        self.timestamp = time.time()

    @property
    def passed(self) -> bool:
        """True if no delegation violations were detected."""
        return self.chain_valid and len(self.violations) == 0

    def summary(self) -> str:
        lines = [
            "━" * 60,
            "  EVALUATION RESULT",
            "━" * 60,
            f"  Task              : {self.task}",
            f"  Agents involved   : {' → '.join(self.agents_involved)}",
            f"  Proofs collected  : {len(self.proof_chain)}",
            f"  Duration          : {self.duration_seconds:.3f}s",
            f"  Chain valid       : {'✅ YES' if self.chain_valid else '❌ NO'}",
            f"  Violations        : {len(self.violations)}",
        ]
        if self.violations:
            lines.append("  Violation details :")
            for v in self.violations:
                lines.append(f"    ✗ {v}")
        lines.append(f"  Final verdict     : {'✅ PASS' if self.passed else '❌ FAIL'}")
        lines.append("━" * 60)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "task": self.task,
            "timestamp": self.timestamp,
            "chain_valid": self.chain_valid,
            "violations": self.violations,
            "passed": self.passed,
            "agents_involved": self.agents_involved,
            "proof_count": len(self.proof_chain),
            "duration_seconds": self.duration_seconds,
            "proofs": self.proof_chain.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class GreenAgent(BaseAgent):
    """
    The evaluator agent in AgentBeats + ADF.

    Responsibilities:
    - Issue and register the root capability.
    - Assign tasks to the PurpleAgent.
    - Collect all ExecutionProofs from the delegation chain.
    - Verify delegation correctness via the CapabilityRegistry.
    - Produce a structured EvaluationResult.
    """

    def __init__(self, agent_id: str, registry: CapabilityRegistry):
        # The GreenAgent does not need a capability for itself —
        # it is the trust anchor. We pass a dummy subject here.
        super().__init__(agent_id, registry)

    def evaluate(
        self,
        purple_agent: PurpleAgent,
        task: str,
        root_capability: Capability,
    ) -> EvaluationResult:
        """
        Run a full ADF evaluation against a PurpleAgent.

        Args:
            purple_agent:     The agent under test.
            task:             The task description to assign.
            root_capability:  The root capability to issue (already signed).

        Returns:
            An EvaluationResult with full chain verification details.
        """
        print("\n" + "═" * 60)
        print(f"  GREEN AGENT [{self.agent_id}]: Starting evaluation")
        print(f"  Task     : '{task}'")
        print(f"  Purple   : {purple_agent.agent_id}")
        print(f"  Root cap : {root_capability}")
        print("═" * 60)

        # Register root capability
        self.registry.register(root_capability)

        start = time.time()

        # Run the purple agent
        proofs = purple_agent.run(task, root_capability)

        duration = time.time() - start

        # Collect all proofs into a chain
        proof_chain = ProofChain()
        proof_chain.extend(proofs)

        # Verify proof integrity
        proofs_valid, proof_errors = proof_chain.verify_all()

        # Verify delegation chain for every capability used
        violations: list[str] = list(proof_errors)
        for cap_id in proof_chain.capability_ids_used():
            chain_valid, chain_errors = self.registry.verify_chain(cap_id)
            violations.extend(chain_errors)

        chain_valid = len(violations) == 0

        result = EvaluationResult(
            task=task,
            chain_valid=chain_valid,
            violations=violations,
            proof_chain=proof_chain,
            agents_involved=proof_chain.agents_involved(),
            duration_seconds=duration,
        )

        print(result.summary())
        return result
