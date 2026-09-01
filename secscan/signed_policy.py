from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from secscan.policy import load_policy

SCHEMA_VERSION = 1
ALGORITHM = "Ed25519"
MAX_POLICY_BYTES = 1024 * 1024
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
BUNDLE_KEYS = {
    "schema_version",
    "bundle_id",
    "version",
    "algorithm",
    "signer_sha256",
    "policy_sha256",
    "policy_b64",
    "provenance",
    "signature",
}
PROVENANCE_KEYS = {"source"}


def _require_identifier(value: str, label: str) -> str:
    candidate = value.strip()
    if not _IDENTIFIER.fullmatch(candidate):
        raise ValueError(f"{label} must contain only letters, numbers, '.', '_' or '-' (1-128 characters)")
    return candidate


def _require_source(value: str) -> str:
    candidate = value.strip()
    if not candidate or len(candidate) > 512 or any(ord(char) < 32 for char in candidate):
        raise ValueError("source must be 1-512 printable characters")
    return candidate


def _canonical_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _public_fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"unable to read private key: {path}") from exc
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("private key must be an unencrypted Ed25519 PEM key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key must be Ed25519")
    return key


def _load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"unable to read public key: {path}") from exc
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError as exc:
        raise ValueError("public key must be an Ed25519 PEM key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key must be Ed25519")
    return key


def _exclusive_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError as exc:
        raise ValueError(f"refusing to overwrite existing file: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def generate_keypair(private_path: Path, public_path: Path) -> str:
    if private_path == public_path:
        raise ValueError("private and public key paths must differ")
    if private_path.exists() or public_path.exists():
        existing = private_path if private_path.exists() else public_path
        raise ValueError(f"refusing to overwrite existing file: {existing}")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _exclusive_write(private_path, private_pem, 0o600)
    try:
        _exclusive_write(public_path, public_pem, 0o644)
    except Exception:
        private_path.unlink(missing_ok=True)
        raise
    return _public_fingerprint(public_key)


def build_signed_bundle(
    policy_path: Path,
    private_key_path: Path,
    *,
    bundle_id: str,
    version: str,
    source: str,
) -> dict[str, Any]:
    load_policy(policy_path)
    try:
        policy_bytes = policy_path.read_bytes()
    except OSError as exc:
        raise ValueError(f"unable to read policy file: {policy_path}") from exc
    if not policy_bytes or len(policy_bytes) > MAX_POLICY_BYTES:
        raise ValueError(f"policy must contain 1-{MAX_POLICY_BYTES} bytes")
    try:
        policy_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("policy must be UTF-8") from exc

    private_key = _load_private_key(private_key_path)
    public_key = private_key.public_key()
    unsigned: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "bundle_id": _require_identifier(bundle_id, "bundle id"),
        "version": _require_identifier(version, "version"),
        "algorithm": ALGORITHM,
        "signer_sha256": _public_fingerprint(public_key),
        "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "policy_b64": base64.b64encode(policy_bytes).decode("ascii"),
        "provenance": {"source": _require_source(source)},
    }
    signature = private_key.sign(_canonical_bytes(unsigned))
    return {**unsigned, "signature": base64.b64encode(signature).decode("ascii")}


def write_bundle(document: dict[str, Any], path: Path) -> None:
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _exclusive_write(path, payload, 0o644)


def _load_bundle(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read policy bundle: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("policy bundle must be valid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError("policy bundle must be a JSON object")
    unknown = sorted(set(raw) - BUNDLE_KEYS)
    missing = sorted(BUNDLE_KEYS - set(raw))
    if unknown:
        raise ValueError(f"policy bundle contains unknown keys: {', '.join(unknown)}")
    if missing:
        raise ValueError(f"policy bundle is missing keys: {', '.join(missing)}")
    return raw


def verify_bundle(bundle_path: Path, public_key_path: Path) -> tuple[dict[str, Any], bytes]:
    document = _load_bundle(bundle_path)
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported policy bundle schema: {document['schema_version']}")
    if document["algorithm"] != ALGORITHM:
        raise ValueError(f"unsupported policy bundle algorithm: {document['algorithm']}")
    _require_identifier(str(document["bundle_id"]), "bundle id")
    _require_identifier(str(document["version"]), "version")
    provenance = document["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != PROVENANCE_KEYS:
        raise ValueError("policy bundle provenance must contain only source")
    _require_source(str(provenance["source"]))

    try:
        policy_bytes = base64.b64decode(str(document["policy_b64"]), validate=True)
        signature = base64.b64decode(str(document["signature"]), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("policy bundle contains invalid base64") from exc
    if not policy_bytes or len(policy_bytes) > MAX_POLICY_BYTES:
        raise ValueError(f"policy bundle policy must contain 1-{MAX_POLICY_BYTES} bytes")
    try:
        policy_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("policy bundle policy must be UTF-8") from exc
    if hashlib.sha256(policy_bytes).hexdigest() != document["policy_sha256"]:
        raise ValueError("policy bundle digest does not match policy content")

    public_key = _load_public_key(public_key_path)
    if _public_fingerprint(public_key) != document["signer_sha256"]:
        raise ValueError("policy bundle signer fingerprint does not match public key")
    unsigned = {key: value for key, value in document.items() if key != "signature"}
    try:
        public_key.verify(signature, _canonical_bytes(unsigned))
    except InvalidSignature as exc:
        raise ValueError("policy bundle signature verification failed") from exc

    with tempfile.TemporaryDirectory(prefix="secscan-policy-") as directory:
        policy_path = Path(directory) / "policy.yaml"
        policy_path.write_bytes(policy_bytes)
        load_policy(policy_path)
    return document, policy_bytes


def extract_verified_policy(bundle_path: Path, public_key_path: Path, output_path: Path) -> dict[str, Any]:
    document, policy_bytes = verify_bundle(bundle_path, public_key_path)
    _exclusive_write(output_path, policy_bytes, 0o644)
    return document


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secscan-policy", description="Create and verify signed secscan policy bundles")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="generate an Ed25519 policy-signing keypair")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)

    sign = subparsers.add_parser("sign", help="sign one validated YAML policy into a portable bundle")
    sign.add_argument("policy", type=Path)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--bundle-id", required=True)
    sign.add_argument("--version", required=True)
    sign.add_argument("--source", default="local")
    sign.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify", help="verify a signed policy bundle offline")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--extract-policy", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "keygen":
            fingerprint = generate_keypair(args.private_key, args.public_key)
            print(f"Generated Ed25519 policy keypair; signer_sha256={fingerprint}")
            return 0
        if args.command == "sign":
            document = build_signed_bundle(
                args.policy,
                args.private_key,
                bundle_id=args.bundle_id,
                version=args.version,
                source=args.source,
            )
            write_bundle(document, args.output)
            print(
                f"Signed policy bundle {document['bundle_id']} version {document['version']} "
                f"to {args.output}"
            )
            return 0
        if args.command == "verify":
            if args.extract_policy:
                document = extract_verified_policy(args.bundle, args.public_key, args.extract_policy)
            else:
                document, _ = verify_bundle(args.bundle, args.public_key)
            print(
                f"Verified policy bundle {document['bundle_id']} version {document['version']} "
                f"signer_sha256={document['signer_sha256']}"
            )
            return 0
        return 1
    except ValueError as exc:
        print(f"secscan-policy error: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
