"""
adf/proof.py
============
Cryptographic execution proofs for ADF.

Every time an agent executes a task under a capability, it produces an
ExecutionProof — a tamper-evident record that can be collected and verified
by the GreenAgent at the end of the evaluation run.

The proof chain allows the GreenAgent to reconstruct and audit the full
delegation tree, not just the final output.
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ExecutionProof:
    """
    A tamper-evident record of an agent's action under a specific capability.

    Attributes:
        proof_id:       Unique identifier for this proof.
        agent_id:       The agent that performed the action.
        capability_id:  The capability under which the action was authorized.
        action:         Human-readable description of the action taken.
        result:         Outcome of the action (success message, output, etc.)
        timestamp:      Unix timestamp of execution.
        parent_proof_id: ID of the proof that triggered this one (for tree reconstruction).
        metadata:       Optional additional structured data (e.g. latency, tokens used).
        proof_hash:     SHA-256 hash of the proof content (computed on init).
    """
    proof_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    capability_id: str = ""
    action: str = ""
    result: str = ""
    timestamp: float = field(default_factory=time.time)
    parent_proof_id: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    proof_hash: str = field(default="", init=False)

    def __post_init__(self):
        self.proof_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute a SHA-256 hash of the proof's core fields."""
        content = json.dumps({
            "proof_id": self.proof_id,
            "agent_id": self.agent_id,
            "capability_id": self.capability_id,
            "action": self.action,
            "result": self.result,
            "timestamp": self.timestamp,
            "parent_proof_id": self.parent_proof_id,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def verify(self) -> bool:
        """Return True if the proof has not been tampered with."""
        return self.proof_hash == self._compute_hash()

    def to_dict(self) -> dict:
        return {
            "proof_id": self.proof_id,
            "agent_id": self.agent_id,
            "capability_id": self.capability_id,
            "action": self.action,
            "result": self.result,
            "timestamp": self.timestamp,
            "parent_proof_id": self.parent_proof_id,
            "metadata": self.metadata,
            "proof_hash": self.proof_hash,
            "verified": self.verify(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def __repr__(self) -> str:
        status = "✓" if self.verify() else "✗ TAMPERED"
        return (
            f"ExecutionProof({status} "
            f"agent={self.agent_id!r}, "
            f"action={self.action!r}, "
            f"hash={self.proof_hash[:12]}...)"
        )


class ProofChain:
    """
    An ordered, append-only collection of ExecutionProofs.

    Used by the GreenAgent to collect and verify the full execution
    trace of a delegation chain.
    """

    def __init__(self):
        self._proofs: list[ExecutionProof] = []

    def append(self, proof: ExecutionProof) -> None:
        """Add a proof to the chain."""
        self._proofs.append(proof)

    def extend(self, proofs: list[ExecutionProof]) -> None:
        """Add multiple proofs to the chain."""
        self._proofs.extend(proofs)

    def verify_all(self) -> tuple[bool, list[str]]:
        """
        Verify every proof in the chain.

        Returns:
            (all_valid, list_of_error_messages)
        """
        errors = []
        for proof in self._proofs:
            if not proof.verify():
                errors.append(f"Proof {proof.proof_id[:8]}... from agent {proof.agent_id!r} is INVALID.")
        return len(errors) == 0, errors

    def agents_involved(self) -> list[str]:
        """Return the ordered list of agent IDs that participated in the chain."""
        seen = []
        for proof in self._proofs:
            if proof.agent_id not in seen:
                seen.append(proof.agent_id)
        return seen

    def capability_ids_used(self) -> set[str]:
        """Return the set of capability IDs referenced in this chain."""
        return {p.capability_id for p in self._proofs}

    def to_dict(self) -> dict:
        return {
            "total_proofs": len(self._proofs),
            "agents_involved": self.agents_involved(),
            "capability_ids_used": list(self.capability_ids_used()),
            "proofs": [p.to_dict() for p in self._proofs],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def __len__(self) -> int:
        return len(self._proofs)

    def __iter__(self):
        return iter(self._proofs)

    def __repr__(self) -> str:
        return f"ProofChain(proofs={len(self._proofs)}, agents={self.agents_involved()})"
