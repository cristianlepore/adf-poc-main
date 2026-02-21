"""
adf/registry.py
===============
The Capability Registry is a central authority that tracks all issued capabilities,
supports revocation, and allows chain reconstruction.

In a production deployment, this would be a distributed ledger or a
tamper-evident append-only log. For this proof-of-concept, it is an
in-memory store with optional JSON persistence.
"""

import json
import time
from typing import Optional

from adf.capability import Capability


class RegistryError(Exception):
    """Raised when a registry operation fails."""
    pass


class CapabilityRegistry:
    """
    Central registry for tracking, looking up, and revoking capabilities.

    Key operations:
    - register(): record a new capability after issuance
    - revoke():   mark a capability (and its descendants) as revoked
    - lookup():   retrieve a capability by ID
    - is_revoked(): check if a capability has been revoked
    - chain():    reconstruct the full delegation chain for a given capability
    """

    def __init__(self):
        # capability_id -> Capability
        self._store: dict[str, Capability] = {}
        # Set of revoked capability IDs
        self._revoked: set[str] = set()
        # Audit log of registry events
        self._audit_log: list[dict] = []

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, capability: Capability) -> None:
        """
        Register a newly issued capability.

        Args:
            capability: A signed Capability instance.

        Raises:
            RegistryError: If the capability signature is invalid.
        """
        if not capability.verify_signature():
            raise RegistryError(
                f"Cannot register capability {capability.capability_id[:8]}...: invalid signature."
            )
        self._store[capability.capability_id] = capability
        self._log("register", capability.capability_id, capability.issuer, capability.subject)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def lookup(self, capability_id: str) -> Optional[Capability]:
        """Return the capability with the given ID, or None if not found."""
        return self._store.get(capability_id)

    def exists(self, capability_id: str) -> bool:
        """Return True if the capability ID is registered."""
        return capability_id in self._store

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def revoke(self, capability_id: str, reason: str = "No reason provided.") -> int:
        """
        Revoke a capability and all its descendants (cascade revocation).

        Args:
            capability_id: The ID of the capability to revoke.
            reason:        Human-readable reason for revocation.

        Returns:
            The number of capabilities revoked (including descendants).

        Raises:
            RegistryError: If the capability ID is not registered.
        """
        if capability_id not in self._store:
            raise RegistryError(f"Capability {capability_id[:8]}... not found in registry.")

        revoked_ids = self._cascade_revoke(capability_id)
        for cid in revoked_ids:
            self._log("revoke", cid, reason=reason)

        return len(revoked_ids)

    def _cascade_revoke(self, capability_id: str) -> list[str]:
        """Recursively revoke a capability and all capabilities that descend from it."""
        revoked = []
        queue = [capability_id]
        while queue:
            current_id = queue.pop()
            if current_id not in self._revoked:
                self._revoked.add(current_id)
                revoked.append(current_id)
            # Find all children
            for cap in self._store.values():
                if cap.parent_id == current_id and cap.capability_id not in self._revoked:
                    queue.append(cap.capability_id)
        return revoked

    def is_revoked(self, capability_id: str) -> bool:
        """Return True if the capability has been revoked."""
        return capability_id in self._revoked

    def is_fully_valid(self, capability: Capability) -> bool:
        """
        Return True if the capability is valid AND not revoked.
        This is the primary check agents should use before acting.
        """
        return capability.is_valid() and not self.is_revoked(capability.capability_id)

    # ------------------------------------------------------------------
    # Chain Reconstruction
    # ------------------------------------------------------------------

    def chain(self, capability_id: str) -> list[Capability]:
        """
        Reconstruct the full delegation chain from root to the given capability.

        Returns:
            List of capabilities from root (index 0) to target (last index).

        Raises:
            RegistryError: If any link in the chain is missing from the registry.
        """
        result = []
        current_id = capability_id
        while current_id is not None:
            cap = self.lookup(current_id)
            if cap is None:
                raise RegistryError(
                    f"Broken chain: capability {current_id[:8]}... not found in registry."
                )
            result.append(cap)
            current_id = cap.parent_id
        result.reverse()
        return result

    def verify_chain(self, capability_id: str) -> tuple[bool, list[str]]:
        """
        Verify the full delegation chain for a capability.

        Checks:
        - Every link in the chain is registered and has a valid signature.
        - No link is revoked.
        - Each child's valid_until does not exceed its parent's valid_until.
        - Numeric permissions are non-increasing along the chain.

        Returns:
            (all_valid, list_of_error_messages)
        """
        errors = []
        try:
            chain = self.chain(capability_id)
        except RegistryError as e:
            return False, [str(e)]

        for i, cap in enumerate(chain):
            if not cap.verify_signature():
                errors.append(f"[{cap.capability_id[:8]}] Invalid signature.")
            if self.is_revoked(cap.capability_id):
                errors.append(f"[{cap.capability_id[:8]}] Capability is revoked.")
            if i > 0:
                parent = chain[i - 1]
                if cap.valid_until > parent.valid_until:
                    errors.append(
                        f"[{cap.capability_id[:8]}] valid_until exceeds parent's valid_until."
                    )
                for key, value in cap.permissions.items():
                    if key in parent.permissions:
                        pv = parent.permissions[key]
                        if isinstance(value, (int, float)) and isinstance(pv, (int, float)):
                            if value > pv:
                                errors.append(
                                    f"[{cap.capability_id[:8]}] Permission '{key}' increased: "
                                    f"{pv} → {value}."
                                )

        return len(errors) == 0, errors

    # ------------------------------------------------------------------
    # Audit Log
    # ------------------------------------------------------------------

    def _log(self, event: str, capability_id: str, issuer: str = "", subject: str = "", reason: str = "") -> None:
        self._audit_log.append({
            "timestamp": time.time(),
            "event": event,
            "capability_id": capability_id,
            "issuer": issuer,
            "subject": subject,
            "reason": reason,
        })

    def audit_log(self) -> list[dict]:
        """Return the full audit log."""
        return list(self._audit_log)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        return {
            "total_registered": len(self._store),
            "total_revoked": len(self._revoked),
            "total_active": sum(1 for c in self._store.values() if c.is_valid() and not self.is_revoked(c.capability_id)),
            "total_expired": sum(1 for c in self._store.values() if c.is_expired()),
        }

    def __repr__(self) -> str:
        s = self.stats()
        return (
            f"CapabilityRegistry("
            f"registered={s['total_registered']}, "
            f"active={s['total_active']}, "
            f"revoked={s['total_revoked']}, "
            f"expired={s['total_expired']})"
        )
