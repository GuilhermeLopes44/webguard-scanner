from __future__ import annotations

import copy
import threading

from core.auth import TargetAuth
from core.config import AppConfig, load_config
from core.engine import ScanEngine
from core.logging_setup import get_logger
from core.models import ScanStatus
from db.database import create_scan, finalize_scan, update_scan_progress

log = get_logger(__name__)

_lock = threading.Lock()
_active_threads: dict[int, threading.Thread] = {}


def enqueue_scan(
    target_url: str,
    config: AppConfig | None = None,
    auth: TargetAuth | None = None,
) -> int:
    cfg = copy.deepcopy(config) if config else load_config()
    if auth is not None:
        cfg.target_auth = auth
    scan_id = create_scan(target_url)

    def worker() -> None:
        update_scan_progress(scan_id, "Starting", 1, status=ScanStatus.RUNNING.value)

        def on_progress(message: str, percent: int) -> None:
            update_scan_progress(scan_id, message, percent, status=ScanStatus.RUNNING.value)

        engine = ScanEngine(cfg)
        result = engine.run(target_url, progress_cb=on_progress, auth=cfg.target_auth)
        finalize_scan(scan_id, result)
        with _lock:
            _active_threads.pop(scan_id, None)

    thread = threading.Thread(target=worker, name=f"webguard-scan-{scan_id}", daemon=True)
    with _lock:
        _active_threads[scan_id] = thread
    thread.start()
    log.info("Enqueued scan %s for %s", scan_id, target_url)
    return scan_id
