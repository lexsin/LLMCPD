from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .common import ContractError, beneath, decode, digest, dumps, file_hash


@dataclass(frozen=True)
class Release:
    path: Path
    version: str
    manifest: dict


class Releases:
    def __init__(self, root, default):
        self.root, self.default = Path(root), default

    def get(self, version=None):
        ident = (version or self.default).split("+sha256:", 1)[0]
        path = beneath(self.root, ident)
        try:
            raw = (path / "release.json").read_bytes()
            manifest = decode(raw.decode("utf-8"), "release manifest")
        except OSError as exc:
            raise ContractError("RELEASE_MISSING", f"fixed release {ident} is unavailable") from exc
        if not isinstance(manifest, dict) or any(k not in manifest for k in ("release_id", "upstream", "files", "adapter_files")):
            raise ContractError("RELEASE_FORMAT", "release manifest is incomplete")
        for field in ("files", "adapter_files"):
            entries = manifest[field]
            if not isinstance(entries, dict) or not entries or any(
                not isinstance(name, str) or not isinstance(value, str) or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)
                for name, value in entries.items()
            ):
                raise ContractError("RELEASE_FORMAT", f"invalid SHA-256 inventory: {field}")
        canonical = dumps({k: manifest[k] for k in ("release_id", "upstream", "files", "adapter_files")})
        actual_version = ident + "+sha256:" + digest(canonical.encode("utf-8"))
        if manifest["release_id"] != ident or (version and version != actual_version):
            raise ContractError("RELEASE_MISMATCH", "release identifier/hash mismatch")
        for name, expected in manifest["files"].items():
            file = beneath(path, name)
            if not file.is_file() or file_hash(file) != expected:
                raise ContractError("RELEASE_MISMATCH", f"release file differs: {name}")
        actual_files = {p.name for p in path.glob("*.py")}
        if actual_files != {n for n in manifest["files"] if n.endswith(".py")}:
            raise ContractError("RELEASE_MISMATCH", "unexpected executable file in release")
        service_root = Path(__file__).resolve().parents[2]
        for relative, expected in manifest["adapter_files"].items():
            file = beneath(service_root, relative)
            if not file.is_file() or file_hash(file) != expected:
                raise ContractError("ADAPTER_MISMATCH", f"restore the adapter version bound to this release: {relative}")
        return Release(path, actual_version, manifest)


def frozen_rules(run, release):
    import yaml
    snapshot, expected = run.get("rule_snapshot_json"), run.get("rule_hash")
    if bool(snapshot) != bool(expected):
        raise ContractError("RULE_PAIR", "rule snapshot and hash must be provided together")
    if not snapshot:
        if run.get("started_at"):
            raise ContractError("RULE_MISSING", "started run cannot recreate missing rules")
        content = (release.path / "llm_scan_rules.yaml").read_bytes().decode("utf-8")
        snapshot = {"schema_version": 1, "format": "YAML", "content": content}
        expected = digest(content.encode("utf-8"))
    else:
        snapshot = decode(snapshot, "rule snapshot")
        if snapshot.get("schema_version") != 1 or snapshot.get("format") != "YAML" or not isinstance(snapshot.get("content"), str):
            raise ContractError("RULE_FORMAT", "unsupported rule snapshot")
        content = snapshot["content"]
    if digest(content.encode("utf-8")) != expected:
        raise ContractError("RULE_HASH", "rule content does not match frozen hash")
    try:
        if not isinstance(yaml.safe_load(content), dict):
            raise ValueError("rules must be a YAML mapping")
    except (yaml.YAMLError, ValueError) as exc:
        raise ContractError("RULE_FORMAT", "rule snapshot is not a valid YAML mapping") from exc
    return snapshot, expected
