"""
adf/agents/base.py
==================
Base class for all ADF-aware agents.

Every agent in ADF — whether a green (evaluator) or purple (competing) agent —
shares this foundation. It provides:
- Capability validation before any action
- Automatic ExecutionProof generation
- Registry integration for revocation checks
"""

from adf.capability import Capability
from adf.proof import ExecutionProof, ProofChain
from adf.registry import CapabilityRegistry


class AgentError(Exception):
    """Raised when an agent encounters an ADF violation."""
    pass


class BaseAgent:
    """
    ADF-aware agent base class.

    Subclasses must implement `think()` to define the agent's reasoning logic.
    In a real deployment, think() would call an LLM API (e.g. OpenAI, Anthropic).
    """

    def __init__(self, agent_id: str, registry: CapabilityRegistry):
        """
        Args:
            agent_id: Unique identifier for this agent (e.g. 'chatgpt_agent').
            registry: Shared CapabilityRegistry for revocation checks and chain verification.
        """
        self.agent_id = agent_id
        self.registry = registry
        self.proof_chain = ProofChain()

    # ------------------------------------------------------------------
    # Core: think + execute
    # ------------------------------------------------------------------

    def think(self, task: str, capability: Capability) -> str:
        """
        Reasoning step. Returns a string describing the planned or completed action.

        Override this method to integrate a real LLM:
            response = openai.chat.completions.create(...)
            return response.choices[0].message.content

        Args:
            task:       The task description received from the delegating agent.
            capability: The capability under which this agent is authorized.

        Returns:
            A string describing the result of the reasoning/action.
        """
        return (
            f"[{self.agent_id}] Executed task: '{task}' "
            f"with permissions {capability.permissions}"
        )

    def execute(
        self,
        task: str,
        capability: Capability,
        parent_proof_id: str = None,
    ) -> ExecutionProof:
        """
        Validate the capability and execute the task, producing an ExecutionProof.

        Validation steps:
        1. Verify the capability's cryptographic signature.
        2. Check the capability is active (not expired, not yet valid).
        3. Check the capability has not been revoked in the registry.
        4. Verify the capability is addressed to this agent.

        Args:
            task:            The task to execute.
            capability:      The delegated capability authorizing this action.
            parent_proof_id: The proof ID of the action that triggered this one.

        Returns:
            A signed ExecutionProof.

        Raises:
            AgentError: If any capability check fails.
        """
        self._validate_capability(capability)

        result = self.think(task, capability)

        proof = ExecutionProof(
            agent_id=self.agent_id,
            capability_id=capability.capability_id,
            action=task,
            result=result,
            parent_proof_id=parent_proof_id,
        )
        self.proof_chain.append(proof)

        print(f"    ✓ {proof}")
        return proof

    # ------------------------------------------------------------------
    # Delegation
    # ------------------------------------------------------------------

    def delegate(
        self,
        sub_agent: "BaseAgent",
        task: str,
        capability: Capability,
        reduced_permissions: dict,
        duration_seconds: int = 3600,
        parent_proof_id: str = None,
    ) -> list[ExecutionProof]:
        """
        Attenuate the current capability and delegate a task to a sub-agent.

        The attenuated capability is registered in the shared registry before
        the sub-agent executes, so it can be verified and potentially revoked.

        Args:
            sub_agent:           The agent receiving the delegation.
            task:                The task to delegate.
            capability:          The current agent's capability (to be attenuated).
            reduced_permissions: Permissions for the sub-agent (must be ⊆ capability.permissions).
            duration_seconds:    Lifetime of the attenuated capability.
            parent_proof_id:     Proof ID of the action triggering this delegation.

        Returns:
            List of ExecutionProofs produced by the sub-agent and its descendants.
        """
        print(f"\n  [{self.agent_id}] → Delegating to [{sub_agent.agent_id}]")

        attenuated = capability.attenuate(
            new_subject=sub_agent.agent_id,
            reduced_permissions=reduced_permissions,
            duration_seconds=duration_seconds,
        )
        self.registry.register(attenuated)
        print(f"    Attenuated capability: {attenuated}")

        return sub_agent.run(task, attenuated, parent_proof_id=parent_proof_id)

    # ------------------------------------------------------------------
    # Main entry point (override in subclasses)
    # ------------------------------------------------------------------

    def run(self, task: str, capability: Capability, parent_proof_id: str = None) -> list[ExecutionProof]:
        """
        Main execution entry point. Override in subclasses to implement
        agent-specific logic (e.g. multi-hop delegation, tool use, etc.)
        """
        proof = self.execute(task, capability, parent_proof_id=parent_proof_id)
        return [proof]

    # ------------------------------------------------------------------
    # Internal validation
    # ------------------------------------------------------------------

    def _validate_capability(self, capability: Capability) -> None:
        """Run all ADF capability checks. Raises AgentError on any failure."""
        if not capability.verify_signature():
            raise AgentError(
                f"[{self.agent_id}] Capability {capability.capability_id[:8]}... "
                f"has an invalid signature. Possible tampering."
            )
        if capability.is_expired():
            raise AgentError(
                f"[{self.agent_id}] Capability {capability.capability_id[:8]}... has expired."
            )
        if not capability.is_active():
            raise AgentError(
                f"[{self.agent_id}] Capability {capability.capability_id[:8]}... is not yet active."
            )
        if self.registry.is_revoked(capability.capability_id):
            raise AgentError(
                f"[{self.agent_id}] Capability {capability.capability_id[:8]}... has been revoked."
            )
        if capability.subject != self.agent_id:
            raise AgentError(
                f"[{self.agent_id}] Capability is addressed to '{capability.subject}', not to this agent."
            )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.agent_id!r})"
