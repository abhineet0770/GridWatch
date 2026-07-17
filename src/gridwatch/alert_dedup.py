"""
Deduplication and rate-limiting layer for GridWatch alert rules.
Suppresses rapid, repeating duplicate alerts while allowing state changes or
periodic reminder alerts after a configured cooldown.
"""

import logging
from datetime import datetime

try:
    from gridwatch import config
except ImportError:
    import config

logger = logging.getLogger("gridwatch.dedup")


class AlertDeduplicator:
    def __init__(self, cooldown_seconds: int = 300):
        """
        Initialize the AlertDeduplicator with a cooldown window in seconds.
        """
        self.cooldown_seconds = cooldown_seconds
        # In-memory store: (rule_id, dedup_key) -> {"fingerprint": str, "last_alert_time": datetime}
        self.alerts = {}

    def should_alert(
        self, rule_id: str, dedup_key: str, fingerprint: str, now: datetime | None = None
    ) -> bool:
        """
        Returns True if this alert should actually be sent (and updates
        internal state), False if it should be suppressed.

        Logic:
        - If (rule_id, dedup_key) has never been seen -> True.
        - Else if fingerprint differs from stored -> True (state changed).
        - Else (same fingerprint) -> True only if cooldown_seconds have elapsed since last_alert_time.
        """
        if now is None:
            now = datetime.now()

        key = (rule_id, dedup_key)
        if key not in self.alerts:
            # First occurrence, always alert
            self.alerts[key] = {
                "fingerprint": fingerprint,
                "last_alert_time": now,
            }
            logger.info(f"Deduplicator: First occurrence of {rule_id} (key: {dedup_key}). Sending alert.")
            return True

        stored = self.alerts[key]
        if fingerprint != stored["fingerprint"]:
            # State genuinely changed
            self.alerts[key] = {
                "fingerprint": fingerprint,
                "last_alert_time": now,
            }
            logger.info(f"Deduplicator: State change for {rule_id} (key: {dedup_key}). Sending alert.")
            return True

        # Same fingerprint, check cooldown window
        elapsed = (now - stored["last_alert_time"]).total_seconds()
        if elapsed >= self.cooldown_seconds:
            stored["last_alert_time"] = now
            logger.info(
                f"Deduplicator: Cooldown expired for {rule_id} (key: {dedup_key}) after {elapsed:.1f}s. Sending reminder."
            )
            return True

        logger.debug(
            f"Deduplicator: Suppressed duplicate {rule_id} (key: {dedup_key}). Cooldown remaining: {self.cooldown_seconds - elapsed:.1f}s."
        )
        return False


# Singleton instance shared across rule detection
deduplicator = AlertDeduplicator(cooldown_seconds=config.DEDUP_COOLDOWN_SECONDS)
