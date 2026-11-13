"""OpenSSL command-line helpers. Used ONLY for setup (keys/certificates), never for timing."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.common.util import parse_version, rsa_bits, short_err

DEFAULT_TIMEOUT_S = 120


def cli_timeout(cfg: dict[str, Any]) -> int:
    """Subprocess timeout from config."""
    return int(cfg.get("tools", {}).get("subprocess_timeout_s", DEFAULT_TIMEOUT_S))


def resolve_openssl_bin(openssl_bin: str) -> str | None:
    """Absolute path of the OpenSSL CLI (from PATH or an explicit file path)."""
    return shutil.which(openssl_bin) or (openssl_bin if Path(openssl_bin).is_file() else None)


def run_cmd(cmd: list[str], timeout: int, cwd: str | Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run a command and capture its output."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, check=False)


def run_checked(cmd: list[str], timeout: int, cwd: str | Path | None = None) -> str:
    """Run a command; raise RuntimeError with stderr on failure."""
    p = run_cmd(cmd, timeout, cwd)
    if p.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(cmd[1:3])} gagal: {(p.stderr or p.stdout).strip()[:400]}")
    return p.stdout


def genpkey_args(alg: str) -> list[str]:
    """`openssl genpkey` arguments for an algorithm name ('RSA-2048', 'ML-DSA-44', ...)."""
    bits = rsa_bits(alg)
    return ["-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}"] if bits else ["-algorithm", alg]


def digest_flag(signer_alg: str, hash_name: str) -> list[str]:
    """Digest flag for certificate signing: only RSA uses an external hash (e.g. SHA-256 -> -sha256)."""
    if rsa_bits(signer_alg) is None:
        return []
    return ["-" + hash_name.lower().replace("-", "")]


def openssl_cli_info(openssl_bin: str, alg_names: list[str], min_ver: tuple[int, ...],
                     timeout: int) -> dict[str, Any]:
    """Locate the OpenSSL CLI and check its version / signature algorithms."""
    path = resolve_openssl_bin(openssl_bin)
    info: dict[str, Any] = {"bin": openssl_bin, "path": path, "version_text": None,
                            "meets_min": False, "sig_algs": {}}
    if not path:
        return info
    try:
        out = run_cmd([path, "version"], timeout).stdout.strip()
        info["version_text"] = out
        info["meets_min"] = parse_version(out) >= min_ver
        listing = run_cmd([path, "list", "-signature-algorithms"], timeout).stdout.lower()
        info["sig_algs"] = {n: (rsa_bits(n) is not None) or n.lower() in listing for n in alg_names}
    except (OSError, subprocess.SubprocessError) as exc:
        info["error"] = short_err(exc)
    return info
