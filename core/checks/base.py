from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from core.models import Finding

if TYPE_CHECKING:
    from core.config import AppConfig
    from core.http_client import RateLimitedSession
    from core.models import CrawlResult


class BaseCheck(ABC):
    check_id: str = "base"
    title: str = "Base check"

    @abstractmethod
    def run(
        self,
        crawl: CrawlResult,
        session: RateLimitedSession,
        config: AppConfig,
    ) -> list[Finding]:
        raise NotImplementedError
