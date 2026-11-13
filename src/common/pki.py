"""Build a two-level PKI (CA + subscriber) with the OpenSSL CLI (setup only, not timed).

Extensions follow SPEC 4.2:
* CA:         basicConstraints CA:TRUE, pathlen:0; keyUsage keyCertSign, cRLSign; SKI/AKI
* subscriber: basicConstraints CA:FALSE; keyUsage digitalSignature, nonRepudiation; SKI/AKI
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.common.opensslcli import digest_flag, genpkey_args, run_checked

EXT_CNF = """\
[ req ]
distinguished_name = req_dn
string_mask = utf8only
[ req_dn ]
[ v3_ca ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[ v3_user ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""

FILES = ("ca.key", "ca.crt", "user.key", "user.crt", "chain.pem")


@dataclass
class ChainPaths:
    """Paths of the files of one PKI."""

    directory: Path

    def __getitem__(self, name: str) -> Path:
        return self.directory / name

    def complete(self) -> bool:
        """True when every expected file exists and is non-empty."""
        return all((self.directory / f).is_file() and (self.directory / f).stat().st_size > 0 for f in FILES)


def subject(cfg: dict[str, Any], cn: str) -> str:
    """Distinguished name string for `openssl -subj` from `cert_profile`."""
    prof = cfg["cert_profile"]
    return f"/C={prof['country']}/O={prof['organization']}/CN={cn}"


def build_chain(exe: str, sub_alg: str, ca_alg: str, cfg: dict[str, Any], out_dir: Path,
                timeout: int, ca_cn: str, user_cn: str,
                ca_days: int | None = None, user_days: int | None = None) -> ChainPaths:
    """Create ca.key, ca.crt (self-signed), user.key, user.crt (signed by CA) and chain.pem in `out_dir`."""
    prof = cfg["cert_profile"]
    ca_days = ca_days if ca_days is not None else int(prof["ca_validity_days"])
    user_days = user_days if user_days is not None else int(prof["subscriber_validity_days"])
    md = digest_flag(ca_alg, prof["hash"])
    out_dir.mkdir(parents=True, exist_ok=True)
    cnf = out_dir / "ext.cnf"
    cnf.write_text(EXT_CNF, encoding="ascii")
    try:
        run_checked([exe, "genpkey", *genpkey_args(ca_alg), "-out", "ca.key"], timeout, out_dir)
        run_checked([exe, "req", "-new", "-x509", "-utf8", "-config", "ext.cnf", "-extensions", "v3_ca",
                     "-key", "ca.key", "-subj", subject(cfg, ca_cn), "-days", str(ca_days), *md,
                     "-out", "ca.crt"], timeout, out_dir)
        run_checked([exe, "genpkey", *genpkey_args(sub_alg), "-out", "user.key"], timeout, out_dir)
        run_checked([exe, "req", "-new", "-x509", "-utf8", "-config", "ext.cnf", "-extensions", "v3_user",
                     "-key", "user.key", "-subj", subject(cfg, user_cn), "-days", str(user_days),
                     "-CA", "ca.crt", "-CAkey", "ca.key", *md, "-out", "user.crt"], timeout, out_dir)
        run_checked([exe, "verify", "-CAfile", "ca.crt", "user.crt"], timeout, out_dir)
    finally:
        cnf.unlink(missing_ok=True)
    paths = ChainPaths(out_dir)
    paths["chain.pem"].write_bytes(paths["user.crt"].read_bytes() + paths["ca.crt"].read_bytes())
    return paths
