"""
RoadAudit - Audit Logging System for BlackRoad
Comprehensive audit trails with tamper detection and compliance features.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import asyncio
import hashlib
import json
import logging
import threading
import time
import uuid

logger = logging.getLogger(__name__)


class AuditAction(str, Enum):
    """Types of auditable actions."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    EXPORT = "export"
    IMPORT = "import"
    APPROVE = "approve"
    REJECT = "reject"
    GRANT = "grant"
    REVOKE = "revoke"
    EXECUTE = "execute"
    CONFIGURE = "configure"


class AuditSeverity(str, Enum):
    """Severity levels for audit events."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditCategory(str, Enum):
    """Categories of audit events."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    CONFIGURATION = "configuration"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    SYSTEM = "system"


@dataclass
class AuditActor:
    """The entity performing an action."""
    id: str
    actor_type: str  # user, service, system, api_key
    name: Optional[str] = None
    email: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.actor_type,
            "name": self.name,
            "email": self.email,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "session_id": self.session_id,
            "roles": self.roles,
            "metadata": self.metadata
        }


@dataclass
class AuditResource:
    """The resource being acted upon."""
    resource_type: str  # user, document, setting, etc.
    resource_id: str
    name: Optional[str] = None
    owner_id: Optional[str] = None
    path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.resource_type,
            "id": self.resource_id,
            "name": self.name,
            "owner_id": self.owner_id,
            "path": self.path,
            "metadata": self.metadata
        }


@dataclass
class AuditChange:
    """Details of a data change."""
    field: str
    old_value: Any = None
    new_value: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "old_value": self._serialize(self.old_value),
            "new_value": self._serialize(self.new_value)
        }

    def _serialize(self, value: Any) -> Any:
        if isinstance(value, datetime):
            return value.isoformat()
        elif hasattr(value, "to_dict"):
            return value.to_dict()
        return value


@dataclass
class AuditEvent:
    """A complete audit event record."""
    id: str
    timestamp: datetime
    action: AuditAction
    category: AuditCategory
    actor: AuditActor
    resource: Optional[AuditResource] = None
    severity: AuditSeverity = AuditSeverity.INFO
    outcome: str = "success"  # success, failure, partial
    description: str = ""
    changes: List[AuditChange] = field(default_factory=list)
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    duration_ms: Optional[float] = None
    error_message: Optional[str] = None
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    hash: Optional[str] = None
    previous_hash: Optional[str] = None

    def compute_hash(self, previous_hash: str = "") -> str:
        """Compute tamper-evident hash."""
        data = json.dumps({
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action.value,
            "actor": self.actor.to_dict(),
            "resource": self.resource.to_dict() if self.resource else None,
            "outcome": self.outcome,
            "previous_hash": previous_hash
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action.value,
            "category": self.category.value,
            "severity": self.severity.value,
            "actor": self.actor.to_dict(),
            "resource": self.resource.to_dict() if self.resource else None,
            "outcome": self.outcome,
            "description": self.description,
            "changes": [c.to_dict() for c in self.changes],
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "parent_event_id": self.parent_event_id,
            "duration_ms": self.duration_ms,
            "error_message": self.error_message,
            "tags": list(self.tags),
            "metadata": self.metadata,
            "hash": self.hash,
            "previous_hash": self.previous_hash
        }


class AuditStore:
    """Store for audit events."""

    def __init__(self, max_events: int = 100000):
        self.events: List[AuditEvent] = []
        self.max_events = max_events
        self.last_hash = ""
        self._lock = threading.Lock()
        self._indexes: Dict[str, Dict[str, List[str]]] = {
            "actor_id": {},
            "resource_id": {},
            "action": {},
            "category": {}
        }

    def append(self, event: AuditEvent) -> None:
        """Append an event with hash chain."""
        with self._lock:
            # Compute hash chain
            event.previous_hash = self.last_hash
            event.hash = event.compute_hash(self.last_hash)
            self.last_hash = event.hash

            self.events.append(event)

            # Update indexes
            self._indexes["actor_id"].setdefault(event.actor.id, []).append(event.id)
            if event.resource:
                self._indexes["resource_id"].setdefault(event.resource.resource_id, []).append(event.id)
            self._indexes["action"].setdefault(event.action.value, []).append(event.id)
            self._indexes["category"].setdefault(event.category.value, []).append(event.id)

            # Prune if needed
            if len(self.events) > self.max_events:
                self._prune()

    def _prune(self) -> None:
        """Remove oldest events."""
        remove_count = len(self.events) - self.max_events
        removed = self.events[:remove_count]
        self.events = self.events[remove_count:]

        # Update indexes
        removed_ids = {e.id for e in removed}
        for index_name in self._indexes:
            for key in self._indexes[index_name]:
                self._indexes[index_name][key] = [
                    eid for eid in self._indexes[index_name][key]
                    if eid not in removed_ids
                ]

    def get(self, event_id: str) -> Optional[AuditEvent]:
        """Get event by ID."""
        for event in self.events:
            if event.id == event_id:
                return event
        return None

    def query(
        self,
        actor_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[AuditAction] = None,
        category: Optional[AuditCategory] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        severity: Optional[AuditSeverity] = None,
        outcome: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditEvent]:
        """Query events with filters."""
        with self._lock:
            # Start with candidate set from indexes if possible
            if actor_id:
                candidates = set(self._indexes["actor_id"].get(actor_id, []))
            elif resource_id:
                candidates = set(self._indexes["resource_id"].get(resource_id, []))
            elif action:
                candidates = set(self._indexes["action"].get(action.value, []))
            elif category:
                candidates = set(self._indexes["category"].get(category.value, []))
            else:
                candidates = None

            results = []
            for event in reversed(self.events):
                if candidates is not None and event.id not in candidates:
                    continue

                if actor_id and event.actor.id != actor_id:
                    continue
                if resource_id and (not event.resource or event.resource.resource_id != resource_id):
                    continue
                if action and event.action != action:
                    continue
                if category and event.category != category:
                    continue
                if start_time and event.timestamp < start_time:
                    continue
                if end_time and event.timestamp > end_time:
                    continue
                if severity and event.severity != severity:
                    continue
                if outcome and event.outcome != outcome:
                    continue

                results.append(event)

            return results[offset:offset + limit]

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """Verify hash chain integrity."""
        errors = []
        previous_hash = ""

        for i, event in enumerate(self.events):
            expected_hash = event.compute_hash(previous_hash)

            if event.previous_hash != previous_hash:
                errors.append(f"Event {i}: previous_hash mismatch")

            if event.hash != expected_hash:
                errors.append(f"Event {i}: hash mismatch (tampering detected)")

            previous_hash = event.hash

        return len(errors) == 0, errors


class AuditLogger:
    """High-level audit logging interface."""

    def __init__(self, store: Optional[AuditStore] = None):
        self.store = store or AuditStore()
        self.hooks: List[Callable[[AuditEvent], None]] = []
        self.filters: List[Callable[[AuditEvent], bool]] = []
        self.enrichers: List[Callable[[AuditEvent], AuditEvent]] = []
        self._async_queue: asyncio.Queue = asyncio.Queue()

    def add_hook(self, hook: Callable[[AuditEvent], None]) -> None:
        """Add post-log hook (e.g., for alerts)."""
        self.hooks.append(hook)

    def add_filter(self, filter_fn: Callable[[AuditEvent], bool]) -> None:
        """Add filter (return False to drop event)."""
        self.filters.append(filter_fn)

    def add_enricher(self, enricher: Callable[[AuditEvent], AuditEvent]) -> None:
        """Add enricher to modify events."""
        self.enrichers.append(enricher)

    def log(
        self,
        action: AuditAction,
        actor: AuditActor,
        category: AuditCategory = AuditCategory.DATA_ACCESS,
        resource: Optional[AuditResource] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        outcome: str = "success",
        description: str = "",
        changes: Optional[List[AuditChange]] = None,
        **kwargs
    ) -> AuditEvent:
        """Log an audit event."""
        event = AuditEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            action=action,
            category=category,
            actor=actor,
            resource=resource,
            severity=severity,
            outcome=outcome,
            description=description,
            changes=changes or [],
            **kwargs
        )

        # Apply enrichers
        for enricher in self.enrichers:
            event = enricher(event)

        # Apply filters
        for filter_fn in self.filters:
            if not filter_fn(event):
                logger.debug(f"Audit event filtered: {event.id}")
                return event

        # Store event
        self.store.append(event)

        # Call hooks
        for hook in self.hooks:
            try:
                hook(event)
            except Exception as e:
                logger.error(f"Audit hook error: {e}")

        logger.debug(f"Audit logged: {action.value} on {resource.resource_type if resource else 'N/A'}")
        return event

    def log_login(
        self,
        actor: AuditActor,
        success: bool,
        method: str = "password",
        **kwargs
    ) -> AuditEvent:
        """Log authentication event."""
        return self.log(
            action=AuditAction.LOGIN,
            actor=actor,
            category=AuditCategory.AUTHENTICATION,
            severity=AuditSeverity.INFO if success else AuditSeverity.WARNING,
            outcome="success" if success else "failure",
            description=f"Login via {method}",
            metadata={"auth_method": method, **kwargs}
        )

    def log_data_access(
        self,
        actor: AuditActor,
        resource: AuditResource,
        action: AuditAction = AuditAction.READ,
        **kwargs
    ) -> AuditEvent:
        """Log data access event."""
        return self.log(
            action=action,
            actor=actor,
            resource=resource,
            category=AuditCategory.DATA_ACCESS,
            description=f"{action.value.capitalize()} {resource.resource_type} {resource.resource_id}",
            **kwargs
        )

    def log_data_change(
        self,
        actor: AuditActor,
        resource: AuditResource,
        action: AuditAction,
        old_data: Optional[Dict[str, Any]] = None,
        new_data: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> AuditEvent:
        """Log data modification with change tracking."""
        changes = []

        if old_data and new_data:
            all_keys = set(old_data.keys()) | set(new_data.keys())
            for key in all_keys:
                old_val = old_data.get(key)
                new_val = new_data.get(key)
                if old_val != new_val:
                    changes.append(AuditChange(field=key, old_value=old_val, new_value=new_val))
        elif new_data:
            for key, value in new_data.items():
                changes.append(AuditChange(field=key, new_value=value))
        elif old_data:
            for key, value in old_data.items():
                changes.append(AuditChange(field=key, old_value=value))

        return self.log(
            action=action,
            actor=actor,
            resource=resource,
            category=AuditCategory.DATA_MODIFICATION,
            changes=changes,
            description=f"{action.value.capitalize()} {resource.resource_type} with {len(changes)} changes",
            **kwargs
        )

    def log_permission_change(
        self,
        actor: AuditActor,
        target_user_id: str,
        action: AuditAction,
        permission: str,
        **kwargs
    ) -> AuditEvent:
        """Log permission/role changes."""
        resource = AuditResource(
            resource_type="user",
            resource_id=target_user_id
        )

        return self.log(
            action=action,
            actor=actor,
            resource=resource,
            category=AuditCategory.AUTHORIZATION,
            severity=AuditSeverity.WARNING,
            description=f"{action.value.capitalize()} permission '{permission}' for user {target_user_id}",
            **kwargs
        )


class AuditContext:
    """Context manager for tracking audit events."""

    _current = threading.local()

    def __init__(
        self,
        audit_logger: AuditLogger,
        actor: AuditActor,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None
    ):
        self.audit_logger = audit_logger
        self.actor = actor
        self.request_id = request_id or str(uuid.uuid4())
        self.correlation_id = correlation_id
        self.events: List[AuditEvent] = []

    def __enter__(self) -> "AuditContext":
        self._current.context = self
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._current.context = None

    @classmethod
    def current(cls) -> Optional["AuditContext"]:
        """Get current audit context."""
        return getattr(cls._current, "context", None)

    def log(self, action: AuditAction, **kwargs) -> AuditEvent:
        """Log event in current context."""
        event = self.audit_logger.log(
            action=action,
            actor=self.actor,
            request_id=self.request_id,
            correlation_id=self.correlation_id,
            **kwargs
        )
        self.events.append(event)
        return event


class ComplianceReporter:
    """Generate compliance reports from audit logs."""

    def __init__(self, store: AuditStore):
        self.store = store

    def access_report(
        self,
        resource_type: str,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """Generate data access report."""
        events = self.store.query(
            category=AuditCategory.DATA_ACCESS,
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )

        filtered = [e for e in events if e.resource and e.resource.resource_type == resource_type]

        by_actor = {}
        by_action = {}

        for event in filtered:
            by_actor[event.actor.id] = by_actor.get(event.actor.id, 0) + 1
            by_action[event.action.value] = by_action.get(event.action.value, 0) + 1

        return {
            "resource_type": resource_type,
            "period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "total_events": len(filtered),
            "by_actor": by_actor,
            "by_action": by_action,
            "unique_actors": len(by_actor)
        }

    def login_report(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """Generate login activity report."""
        events = self.store.query(
            action=AuditAction.LOGIN,
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )

        successful = [e for e in events if e.outcome == "success"]
        failed = [e for e in events if e.outcome == "failure"]

        failed_by_ip = {}
        for event in failed:
            ip = event.actor.ip_address or "unknown"
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

        return {
            "period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "total_attempts": len(events),
            "successful": len(successful),
            "failed": len(failed),
            "failure_rate": len(failed) / len(events) if events else 0,
            "failed_by_ip": failed_by_ip,
            "unique_users": len({e.actor.id for e in events})
        }


# Example usage
def example_usage():
    """Example audit logging usage."""
    audit = AuditLogger()

    # Add alert hook for security events
    def security_alert(event: AuditEvent):
        if event.severity in {AuditSeverity.ERROR, AuditSeverity.CRITICAL}:
            print(f"SECURITY ALERT: {event.description}")

    audit.add_hook(security_alert)

    # Create actor
    actor = AuditActor(
        id="user-123",
        actor_type="user",
        name="Alice",
        email="alice@example.com",
        ip_address="192.168.1.100"
    )

    # Log login
    audit.log_login(actor, success=True, method="oauth")

    # Log data access
    resource = AuditResource(
        resource_type="document",
        resource_id="doc-456",
        name="Quarterly Report"
    )
    audit.log_data_access(actor, resource)

    # Log data change
    audit.log_data_change(
        actor,
        resource,
        AuditAction.UPDATE,
        old_data={"title": "Q1 Report"},
        new_data={"title": "Q1 2024 Report"}
    )

    # Generate report
    reporter = ComplianceReporter(audit.store)
    report = reporter.login_report(
        start_time=datetime.now() - timedelta(days=7),
        end_time=datetime.now()
    )
    print(f"Login report: {report}")
