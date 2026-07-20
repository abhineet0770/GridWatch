"""
Deduplication and rate-limiting layer for GridWatch alert rules.
Suppresses rapid, repeating duplicate alerts while allowing state changes or
periodic reminder alerts after a configured cooldown.
"""

import logging
from collections import deque
from datetime import datetime, timedelta

try:
    from gridwatch import config
except ImportError:
    import config

logger = logging.getLogger("gridwatch.dedup")


class AlertDeduplicator:
    """Deduplication and rate-limiting layer for GridWatch alert rules."""

    def __init__(self, cooldown_seconds: int = 300, ttl_seconds: int | None = None):
        """Initialize deduplicator with cooldown and TTL settings."""
        self.cooldown_seconds = cooldown_seconds
        self.ttl_seconds = ttl_seconds if ttl_seconds is not None else config.DEDUP_TTL_SECONDS
        self.alerts: dict[tuple[str, str], dict] = {}
        self._eviction_queue: deque[tuple[datetime, tuple[str, str]]] = deque()

    def should_alert(
        self, rule_id: str, dedup_key: str, fingerprint: str, now: datetime | None = None
    ) -> bool:
        """Determine if an alert should be sent based on cooldown and TTL boundaries,
        evicting expired entries lazily.
        """
        if now is None:
            now = datetime.now()

        key = (rule_id, dedup_key)

        # Lazy eviction sweep on each call
        while self._eviction_queue:
            expire_time, queue_key = self._eviction_queue[0]
            if now >= expire_time:
                self._eviction_queue.popleft()
                if queue_key in self.alerts:
                    stored = self.alerts[queue_key]
                    actual_expire_time = stored["last_alert_time"] + timedelta(
                        seconds=self.ttl_seconds
                    )
                    if now >= actual_expire_time:
                        self.alerts.pop(queue_key, None)
                        logger.info(
                            f"Deduplicator: TTL expired for {queue_key[0]} "
                            f"(key: {queue_key[1]}). Evicting entry."
                        )
            else:
                break

        # Check if the key exists and if it is expired per its live timestamp
        if key in self.alerts:
            stored = self.alerts[key]
            if (now - stored["last_alert_time"]).total_seconds() >= self.ttl_seconds:
                self.alerts.pop(key, None)
                logger.info(
                    f"Deduplicator: Hot-path TTL expiration for {rule_id} "
                    f"(key: {dedup_key}). Evicting entry."
                )

        if key not in self.alerts:
            # First occurrence, always alert
            self.alerts[key] = {
                "fingerprint": fingerprint,
                "last_alert_time": now,
            }
            expire_time = now + timedelta(seconds=self.ttl_seconds)
            self._eviction_queue.append((expire_time, key))
            logger.info(
                f"Deduplicator: First occurrence of {rule_id} (key: {dedup_key}). Sending alert."
            )
            return True

        stored = self.alerts[key]
        if fingerprint != stored["fingerprint"]:
            # State genuinely changed
            self.alerts[key] = {
                "fingerprint": fingerprint,
                "last_alert_time": now,
            }
            expire_time = now + timedelta(seconds=self.ttl_seconds)
            self._eviction_queue.append((expire_time, key))
            logger.info(
                f"Deduplicator: State change for {rule_id} (key: {dedup_key}). Sending alert."
            )
            return True

        # Same fingerprint, check cooldown window
        elapsed = (now - stored["last_alert_time"]).total_seconds()
        if elapsed >= self.cooldown_seconds:
            stored["last_alert_time"] = now
            expire_time = now + timedelta(seconds=self.ttl_seconds)
            self._eviction_queue.append((expire_time, key))
            logger.info(
                f"Deduplicator: Cooldown expired for {rule_id} (key: {dedup_key}) "
                f"after {elapsed:.1f}s. Sending reminder."
            )
            return True

        logger.debug(
            f"Deduplicator: Suppressed duplicate {rule_id} (key: {dedup_key}). "
            f"Cooldown remaining: {self.cooldown_seconds - elapsed:.1f}s."
        )
        return False


# Singleton instance shared across rule detection
deduplicator = AlertDeduplicator(
    cooldown_seconds=config.DEDUP_COOLDOWN_SECONDS, ttl_seconds=config.DEDUP_TTL_SECONDS
)
