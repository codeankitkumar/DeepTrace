"""Registry of forensic analysis modules.

Modules are intentionally decoupled from the web layer so they can be reused in
scripts, tests, and CLI tools without starting the application.
"""
from __future__ import annotations

from typing import Type

from app.forensics.base import ForensicsModule
from app.forensics.filesystem import FileSystemModule
from app.forensics.evtx import EvtxModule
from app.forensics.browser_history import BrowserHistoryModule
from app.forensics.memory import MemoryModule
from app.forensics.network_logs import NetworkLogModule
from app.forensics.suspicious_files import SuspiciousFilesModule

REGISTRY: dict[str, Type[ForensicsModule]] = {
    cls.name: cls
    for cls in [
        FileSystemModule,
        EvtxModule,
        BrowserHistoryModule,
        MemoryModule,
        NetworkLogModule,
        SuspiciousFilesModule,
    ]
}


def get_module(name: str) -> ForensicsModule:
    if name not in REGISTRY:
        raise KeyError(f"Unknown forensic module '{name}'. Available: {', '.join(REGISTRY)}")
    return REGISTRY[name]()


def list_modules() -> list[dict]:
    return [
        {"name": cls.name, "display_name": cls.display_name,
         "description": cls.description, "supported_types": cls.supported_types}
        for cls in REGISTRY.values()
    ]