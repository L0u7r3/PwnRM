"""
pwnrm.modules — Extensible Module & Plugin Subsystem
Provides base class, registry, and secure plugin discovery for specialized operations.
"""

import os
import stat
import importlib.util
import logging
import re
from pathlib import Path
from typing import Dict, Type, List, Optional, Any


class BaseModule:
    name: str = "base"
    description: str = "Base module"
    author: str = "uziii2208"
    options: Dict[str, dict] = {}

    def __init__(self):
        pass

    def run(self, shell, args: List[str]) -> Any:
        """
        Executes module in the context of PwnShell.
        Returns result dict or None.
        """
        raise NotImplementedError("Modules must implement run()")


class ModuleManager:
    """Manages discovery, integrity verification, registration, and execution of PwnRM modules."""
    def __init__(self):
        self._modules: Dict[str, BaseModule] = {}
        self._load_builtins()

    def register(self, module_cls: Type[BaseModule]) -> bool:
        instance = module_cls()
        name = str(getattr(instance, "name", "")).strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name):
            raise ValueError(f"invalid module name: {name!r}")
        if name in self._modules:
            logging.warning("Refusing to replace registered module: %s", name)
            return False
        self._modules[name] = instance
        return True

    def get_module(self, name: str) -> Optional[BaseModule]:
        return self._modules.get(name.lower())

    def list_modules(self) -> List[dict]:
        return [
            {
                "name": mod.name,
                "description": mod.description,
                "author": getattr(mod, "author", "uziii2208"),
                "options": getattr(mod, "options", {}),
            }
            for mod in self._modules.values()
        ]

    @staticmethod
    def verify_plugin_integrity(path: Path) -> bool:
        """Verifies plugin file permissions and safety before dynamic importing."""
        try:
            if not path.is_file() or path.is_symlink():
                return False
            st = path.stat()
            if os.name == "posix":
                if st.st_uid != os.geteuid():
                    logging.warning("Refusing to load plugin owned by another user: %s", path)
                    return False
                if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    logging.warning("Refusing to load group/world-writable plugin: %s", path)
                    return False
            return True
        except OSError:
            return False

    def load_external_plugin(self, path: Path) -> bool:
        """Securely loads an external plugin from file."""
        if not self.verify_plugin_integrity(path):
            return False
        try:
            spec = importlib.util.spec_from_file_location(f"pwnrm_plugin_{path.stem}", path)
            if not spec or not spec.loader:
                return False
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for attr in dir(mod):
                obj = getattr(mod, attr)
                if isinstance(obj, type) and issubclass(obj, BaseModule) and obj is not BaseModule:
                    return self.register(obj)
            return False
        except Exception as e:
            logging.error("Failed to load external plugin %s: %s", path, e)
            return False

    def _load_builtins(self):
        from .adcs import ADCSModule
        from .kerberos import KerberosModule
        from .entra import EntraModule
        from .creds import CredsModule
        from .evasion import EvasionModule
        from .bloodhound import BloodhoundModule
        from .lateral import LateralModule
        from .playbook import PlaybookModule
        from .vss import VSSModule
        from .coerce import CoerceModule
        from .laps import LAPSModule
        from .acl import ACLModule
        from .token import TokenModule

        builtins = [
            ADCSModule,
            KerberosModule,
            EntraModule,
            CredsModule,
            EvasionModule,
            BloodhoundModule,
            LateralModule,
            PlaybookModule,
            VSSModule,
            CoerceModule,
            LAPSModule,
            ACLModule,
            TokenModule,
        ]
        for b in builtins:
            if not self.register(b):
                raise RuntimeError(f"duplicate built-in module name: {getattr(b, 'name', 'unknown')}")
