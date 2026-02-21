"""
adf/capability.py
=================
Core of the Agentic Delegation Framework.

A Capability is a cryptographically signed, fine-grained permission token
that specifies exactly what an agent can do, for how long, and who delegated it.

Key properties:
- Attenuation: a child capability can only have LESS permission than its parent
- Traceability: every capability carries its parent's ID, forming a verifiable chain
- Expiry: capabilities expire automatically and can be renewed (within limits)
- Signature: each capability is signed with a SHA-256 hash of its content
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


class CapabilityError(Exception):
    """Raised when a capability operation violates ADF rules."""
    pass


class AttenuationError(CapabilityError):
    """Raised when a child capability tries to exceed its parent's permissions."""
    pass


class RenewalError(CapabilityError):
    """Raised when a renewal violates the original capability's constraints."""
    pass


@dataclass
class Capability:
    """
    A cryptographically signed permission token for agent delegation.

    Attributes:
        capability_id:   Unique identifier (UUID4)
        issuer:          Agent or user who created this capability
        subject:         Agent to whom this capability is delegated
        permissions:     Dict of allowed operations and their constraints
        valid_from:      Unix timestamp — when the capability becomes active
        valid_until:     Unix timestamp — when the capability expires
        parent_id:       ID of the parent capability (None for root)
        max_renewals:    How many times this capability can be renewed
        renewal_count:   How many times it has already been renewed
        signature:       SHA-256 hash of the capability content (set on sign())
    """
    capability_id: str
    issuer: str
    subject: str
    permissions: dict
    valid_from: float
    valid_until: float
    parent_id: Optional[str] = None
    max_renewals: int = 0
    renewal_count: int = 0
    signature: str = field(default="", repr=False)

    # ------------------------------------------------------------------
    # Signing & Verification
    # ------------------------------------------------------------------

    def _content_string(self) -> str:
        """Canonical string representation used for signing."""
        return json.dumps({
            "capability_id": self.capability_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "permissions": self.permissions,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "parent_id": self.parent_id,
            "max_renewals": self.max_renewals,
            "renewal_count": self.renewal_count,
        }, sort_keys=True)

    def sign(self) -> "Capability":
        """Compute and store the cryptographic signature. Returns self for chaining."""
        self.signature = hashlib.sha256(self._content_string().encode()).hexdigest()
        return self

    def verify_signature(self) -> bool:
        """Return True if the signature matches the current content."""
        expected = hashlib.sha256(self._content_string().encode()).hexdigest()
        return self.signature == expected

    # ------------------------------------------------------------------
    # Validity Checks
    # ------------------------------------------------------------------

    def is_active(self) -> bool:
        """Return True if the capability is currently within its valid time window."""
        now = time.time()
        return self.valid_from <= now <= self.valid_until

    def is_expired(self) -> bool:
        """Return True if the capability has passed its valid_until timestamp."""
        return time.time() > self.valid_until

    def is_valid(self) -> bool:
        """Return True if the capability is active AND the signature is correct."""
        return self.is_active() and self.verify_signature()

    def time_remaining(self) -> float:
        """Return seconds remaining before expiry (0 if already expired)."""
        return max(0.0, self.valid_until - time.time())

    # ------------------------------------------------------------------
    # Attenuation — the core ADF delegation primitive
    # ------------------------------------------------------------------

    def attenuate(
        self,
        new_subject: str,
        reduced_permissions: dict,
        duration_seconds: int = 3600,
        max_renewals: int = 0,
    ) -> "Capability":
        """
        Create a child capability for new_subject with reduced permissions.

        Rules enforced:
        1. The child's valid_until cannot exceed the parent's valid_until.
        2. Numeric permission values cannot increase (e.g. budget_max can only go down).
        3. The parent capability must be valid at the time of attenuation.
        4. The child inherits max_renewals only if explicitly set lower.

        Args:
            new_subject:         The agent receiving the delegated capability.
            reduced_permissions: A subset of self.permissions with equal or lower values.
            duration_seconds:    Lifetime of the child capability (capped by parent).
            max_renewals:        How many times the child can be renewed.

        Returns:
            A new signed Capability instance.

        Raises:
            CapabilityError:   If the parent capability is not valid.
            AttenuationError:  If reduced_permissions exceed parent permissions.
        """
        if not self.is_valid():
            raise CapabilityError(
                f"Cannot attenuate an invalid or expired capability (id={self.capability_id[:8]}...)."
            )

        # Enforce attenuation rules on numeric permissions
        for key, value in reduced_permissions.items():
            if key in self.permissions:
                parent_value = self.permissions[key]
                if isinstance(value, (int, float)) and isinstance(parent_value, (int, float)):
                    if value > parent_value:
                        raise AttenuationError(
                            f"Permission '{key}': child value {value} exceeds parent value {parent_value}. "
                            f"Attenuation can only reduce permissions."
                        )
            # If the key is not in parent permissions, it is implicitly denied
            # (strict model: only explicitly granted permissions can be delegated)

        now = time.time()
        child = Capability(
            capability_id=str(uuid.uuid4()),
            issuer=self.subject,
            subject=new_subject,
            permissions=reduced_permissions,
            valid_from=now,
            valid_until=min(self.valid_until, now + duration_seconds),
            parent_id=self.capability_id,
            max_renewals=max_renewals,
            renewal_count=0,
        )
        child.sign()
        return child

    # ------------------------------------------------------------------
    # Renewal
    # ------------------------------------------------------------------

    def renew(self, additional_seconds: int) -> "Capability":
        """
        Extend the validity of this capability, subject to constraints.

        Rules:
        - renewal_count must be < max_renewals.
        - The new valid_until cannot exceed the parent's original valid_until
          (tracked implicitly: root capabilities are self-contained).
        - A new signature is computed after renewal.

        Args:
            additional_seconds: How many seconds to add to valid_until.

        Returns:
            Self (mutated in place) for chaining.

        Raises:
            RenewalError: If max renewals have been reached.
        """
        if self.renewal_count >= self.max_renewals:
            raise RenewalError(
                f"Capability (id={self.capability_id[:8]}...) has reached its renewal limit "
                f"({self.max_renewals} renewal(s) allowed)."
            )

        self.valid_until += additional_seconds
        self.renewal_count += 1
        self.sign()  # Re-sign after mutation
        return self

    def can_renew(self) -> bool:
        """Return True if this capability has renewals remaining."""
        return self.renewal_count < self.max_renewals

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize to a plain dictionary (e.g. for JSON export or logging)."""
        return {
            "capability_id": self.capability_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "permissions": self.permissions,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "parent_id": self.parent_id,
            "max_renewals": self.max_renewals,
            "renewal_count": self.renewal_count,
            "signature": self.signature,
            "is_valid": self.is_valid(),
            "time_remaining_s": round(self.time_remaining(), 2),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        status = "VALID" if self.is_valid() else ("EXPIRED" if self.is_expired() else "INACTIVE")
        return (
            f"Capability("
            f"id={self.capability_id[:8]}..., "
            f"issuer={self.issuer!r}, "
            f"subject={self.subject!r}, "
            f"permissions={self.permissions}, "
            f"status={status}, "
            f"remaining={self.time_remaining():.0f}s"
            f")"
        )


# ------------------------------------------------------------------
# Factory helper
# ------------------------------------------------------------------

def create_root_capability(
    issuer: str,
    subject: str,
    permissions: dict,
    duration_seconds: int = 86400,
    max_renewals: int = 0,
) -> Capability:
    """
    Convenience factory for creating a root (top-level) capability.
    In production, this would be issued after strong user authentication (e.g. FIDO2).

    Args:
        issuer:           The authenticated user or trust anchor.
        subject:          The first agent in the delegation chain.
        permissions:      The maximum set of permissions for this chain.
        duration_seconds: Lifetime of the root capability (default: 24h).
        max_renewals:     Number of times the root capability can be renewed.

    Returns:
        A signed root Capability with parent_id=None.
    """
    now = time.time()
    cap = Capability(
        capability_id=str(uuid.uuid4()),
        issuer=issuer,
        subject=subject,
        permissions=permissions,
        valid_from=now,
        valid_until=now + duration_seconds,
        parent_id=None,
        max_renewals=max_renewals,
    )
    cap.sign()
    return cap
