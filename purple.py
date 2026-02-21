"""
adf/agents/purple.py
====================
Purple (competing) agent — the agent under evaluation.

A PurpleAgent receives a task and a root capability from the GreenAgent,
and may internally delegate to sub-agents to complete the task.
Each hop of delegation is governed by ADF attenuation rules.

In a real system, this would be a production AI assistant (e.g. a travel
booking agent, a coding assistant, a research agent).
"""

from adf.capability import Capability
from adf.proof import ExecutionProof
from adf.registry import CapabilityRegistry
from adf.agents.base import BaseAgent


class PurpleAgent(BaseAgent):
    """
    A competing agent that can form multi-hop delegation chains.

    The PurpleAgent executes part of a task itself and delegates
    sub-tasks to its registered sub-agents with attenuated capabilities.

    Args:
        agent_id:    Unique identifier.
        registry:    Shared CapabilityRegistry.
        sub_agents:  Optional list of sub-agents this agent can delegate to.
    """

    def __init__(
        self,
        agent_id: str,
        registry: CapabilityRegistry,
        sub_agents: list[BaseAgent] = None,
    ):
        super().__init__(agent_id, registry)
        self.sub_agents: list[BaseAgent] = sub_agents or []

    def run(
        self,
        task: str,
        capability: Capability,
        parent_proof_id: str = None,
    ) -> list[ExecutionProof]:
        """
        Execute the task and delegate sub-tasks to registered sub-agents.

        Steps:
        1. Execute the planning/orchestration step locally.
        2. For each sub-agent, attenuate the capability and delegate.
        3. Collect and return all proofs from the entire sub-tree.

        Args:
            task:            The task description.
            capability:      The delegated capability for this agent.
            parent_proof_id: Proof ID of the upstream action.

        Returns:
            All ExecutionProofs produced by this agent and its descendants.
        """
        print(f"\n  [{self.agent_id}] Received task: '{task}'")

        all_proofs: list[ExecutionProof] = []

        # Step 1: local planning step
        own_proof = self.execute(
            task=f"[Plan] {task}",
            capability=capability,
            parent_proof_id=parent_proof_id,
        )
        all_proofs.append(own_proof)

        # Step 2: delegate to each sub-agent
        for sub_agent in self.sub_agents:
            reduced = self._compute_reduced_permissions(capability.permissions, sub_agent.agent_id)
            sub_proofs = self.delegate(
                sub_agent=sub_agent,
                task=f"[Sub-task] {task}",
                capability=capability,
                reduced_permissions=reduced,
                parent_proof_id=own_proof.proof_id,
            )
            all_proofs.extend(sub_proofs)

        return all_proofs

    def _compute_reduced_permissions(self, permissions: dict, sub_agent_id: str) -> dict:
        """
        Compute the attenuated permission set for a sub-agent.

        Override this method to implement domain-specific attenuation logic.
        Default behavior: reduce all numeric values by 20%.

        Args:
            permissions:  Parent permissions dict.
            sub_agent_id: ID of the sub-agent receiving the delegation.

        Returns:
            A reduced permissions dict safe to pass to attenuate().
        """
        reduced = {}
        for key, value in permissions.items():
            if isinstance(value, (int, float)):
                # Reduce numeric caps by 20% (e.g. budget, time limits)
                reduced[key] = round(value * 0.8, 2)
            else:
                reduced[key] = value
        return reduced
