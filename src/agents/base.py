"""
Base Agent Abstract Class for CyberSentinel.
Provides standardized lifecycle management, message validation, structured error handling,
and audit trail generation across all autonomous agents.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging
import time

from src.agents.protocols import AgentRole, AgentStatus, AgentMessage

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for all specialized cybersecurity software agents."""

    def __init__(self, role: AgentRole, agent_id: Optional[str] = None):
        self.role = role
        self.agent_id = agent_id or f"{role.value}-{id(self)}"
        self.status = AgentStatus.IDLE
        self.total_tasks_processed = 0
        self.total_errors_encountered = 0
        self.last_execution_time_ms = 0.0

    def create_message(
        self,
        task_id: str,
        recipient: AgentRole,
        payload: Dict[str, Any],
        status: AgentStatus = AgentStatus.SUCCESS,
        error: Optional[str] = None,
    ) -> AgentMessage:
        """Create a validated inter-agent message."""
        return AgentMessage(
            task_id=task_id,
            sender=self.role,
            recipient=recipient,
            status=status,
            payload=payload,
            error=error,
        )

    def execute(self, message: AgentMessage) -> AgentMessage:
        """
        Public execution wrapper with timing, status tracking, and defensive exception handling.
        """
        t0 = time.perf_counter()
        self.status = AgentStatus.PROCESSING
        logger.info(f"[{self.role.value}] Processing task {message.task_id} from {message.sender.value}...")

        try:
            # Validate input message
            self.validate_input(message)
            
            # Delegate to specialized concrete implementation
            response = self.process(message)
            self.status = response.status
            self.total_tasks_processed += 1
            return response

        except Exception as e:
            self.status = AgentStatus.FAILED
            self.total_errors_encountered += 1
            logger.error(f"[{self.role.value}] Error processing task {message.task_id}: {e}", exc_info=True)
            return self.create_message(
                task_id=message.task_id,
                recipient=message.sender,
                payload={},
                status=AgentStatus.FAILED,
                error=str(e),
            )
        finally:
            self.last_execution_time_ms = (time.perf_counter() - t0) * 1000.0
            logger.debug(f"[{self.role.value}] Task {message.task_id} completed in {self.last_execution_time_ms:.2f}ms with status {self.status.value}")

    def validate_input(self, message: AgentMessage) -> None:
        """Basic message structure sanity validation. Overridable by subclasses."""
        if not message.task_id:
            raise ValueError(f"[{self.role.value}] Missing task_id in input message.")
        if message.payload is None:
            raise ValueError(f"[{self.role.value}] Payload cannot be None.")

    @abstractmethod
    def process(self, message: AgentMessage) -> AgentMessage:
        """Concrete agent reasoning and execution logic."""
        pass

