"""Build the simulated PKI with the OpenSSL CLI (setup only, not timed).

Three levels, after the Indonesian PKI: Root CA -> PSrE (issuing CA) -> subscriber.
One root (``pki.root_alg``) is shared by every algorithm; each algorithm gets its own
PSrE (``algorithms.<id>.ca``) and subscriber. Extensions follow SPEC 4.2:

* root:       basicConstraints CA:TRUE, pathlen:1; keyUsage keyCertSign, cRLSign; SKI/AKI
* PSrE:       basicConstraints CA:TRUE, pathlen:0; keyUsage keyCertSign, cRLSign; SKI/AKI
* subscriber: basicConstraints CA:FALSE; keyUsage digitalSignature, nonRepudiation; SKI/AKI

`build_chain` without a root builds the old two-level chain (self-signed CA); it is
only used by the env_check CMS spike.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.common.opensslcli import digest_flag, genpkey_args, run_checked
from src.common.x509util import read_der

EXT_CNF = """\
[ req ]
distinguished_name = req_dn
string_mask = utf8only
[ req_dn ]
[ v3_root ]
basicConstraints = critical, CA:TRUE, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
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

ROOT_FILES = ("root.key", "root.crt")
# root.crt in an algorithm folder is a copy of the shared root certificate (no key)
FILES = ("ca.key", "ca.crt", "user.key", "user.crt", "root.crt", "chain.pem")


@dataclass
class ChainPaths:
    """Paths of the files of one PKI folder (an algorithm's chain, or the shared root)."""

    directory: Path
    files: tuple[str, ...] = FILES

    def __getitem__(self, name: str) -> Path:
        return self.directory / name

    def complete(self) -> bool:
        """True when every expected file exists and is non-empty."""
        return all((self.directory / f).is_file() and (self.directory / f).stat().st_size > 0 for f in self.files)


def root_dir(cfg: dict[str, Any], certs_dir: Path) -> Path:
    """Folder of the shared root CA (``certs/<pki.root_dir>``)."""
    name = cfg["pki"]["root_dir"]
    if name in cfg["algorithms"]:
        raise ValueError(f"pki.root_dir {name!r} bentrok dengan ID algoritma")
    return certs_dir / name


def root_paths(cfg: dict[str, Any], certs_dir: Path) -> ChainPaths:
    """Paths of the shared root CA files."""
    return ChainPaths(root_dir(cfg, certs_dir), ROOT_FILES)


def embedded_certs(cfg: dict[str, Any], paths: ChainPaths) -> list[bytes]:
    """DER certificates embedded in the CMS besides the signer's: PSrE, plus the root if ``pki.embed_root``."""
    certs = [read_der(paths["ca.crt"])]
    if cfg["pki"]["embed_root"]:
        certs.append(read_der(paths["root.crt"]))
    return certs


def subject(cfg: dict[str, Any], cn: str) -> str:
    """Distinguished name string for `openssl -subj` from `cert_profile`."""
    prof = cfg["cert_profile"]
    return f"/C={prof['country']}/O={prof['organization']}/CN={cn}"


def _write_cnf(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    cnf = out_dir / "ext.cnf"
    cnf.write_text(EXT_CNF, encoding="ascii")
    return cnf


def build_root(exe: str, root_alg: str, cfg: dict[str, Any], out_dir: Path, timeout: int, cn: str,
               days: int | None = None) -> ChainPaths:
    """Create root.key and the self-signed root.crt in `out_dir`."""
    prof = cfg["cert_profile"]
    days = days if days is not None else int(prof["root_validity_days"])
    cnf = _write_cnf(out_dir)
    try:
        run_checked([exe, "genpkey", *genpkey_args(root_alg), "-out", "root.key"], timeout, out_dir)
        run_checked([exe, "req", "-new", "-x509", "-utf8", "-config", cnf.name, "-extensions", "v3_root",
                     "-key", "root.key", "-subj", subject(cfg, cn), "-days", str(days),
                     *digest_flag(root_alg, prof["hash"]), "-out", "root.crt"], timeout, out_dir)
    finally:
        cnf.unlink(missing_ok=True)
    return ChainPaths(out_dir, ROOT_FILES)


def build_chain(exe: str, sub_alg: str, ca_alg: str, cfg: dict[str, Any], out_dir: Path,
                timeout: int, ca_cn: str, user_cn: str,
                ca_days: int | None = None, user_days: int | None = None,
                root: tuple[ChainPaths, str] | None = None) -> ChainPaths:
    """Create ca.key/ca.crt (PSrE), user.key/user.crt and chain.pem in `out_dir`.

    With `root` = (root paths, root algorithm) the PSrE certificate is issued by that root,
    root.crt is copied in and chain.pem = user + PSrE + root. Without it the CA is
    self-signed (two levels) and chain.pem = user + CA.
    """
    prof = cfg["cert_profile"]
    ca_days = ca_days if ca_days is not None else int(prof["ca_validity_days"])
    user_days = user_days if user_days is not None else int(prof["subscriber_validity_days"])
    cnf = _write_cnf(out_dir)
    try:
        run_checked([exe, "genpkey", *genpkey_args(ca_alg), "-out", "ca.key"], timeout, out_dir)
        ca_req = [exe, "req", "-new", "-x509", "-utf8", "-config", cnf.name, "-extensions", "v3_ca",
                  "-key", "ca.key", "-subj", subject(cfg, ca_cn), "-days", str(ca_days)]
        if root is None:
            run_checked([*ca_req, *digest_flag(ca_alg, prof["hash"]), "-out", "ca.crt"], timeout, out_dir)
        else:
            rp, root_alg = root
            shutil.copyfile(rp["root.crt"], out_dir / "root.crt")
            run_checked([*ca_req, "-CA", str(rp["root.crt"].resolve()), "-CAkey", str(rp["root.key"].resolve()),
                         *digest_flag(root_alg, prof["hash"]), "-out", "ca.crt"], timeout, out_dir)
        run_checked([exe, "genpkey", *genpkey_args(sub_alg), "-out", "user.key"], timeout, out_dir)
        run_checked([exe, "req", "-new", "-x509", "-utf8", "-config", cnf.name, "-extensions", "v3_user",
                     "-key", "user.key", "-subj", subject(cfg, user_cn), "-days", str(user_days),
                     "-CA", "ca.crt", "-CAkey", "ca.key", *digest_flag(ca_alg, prof["hash"]),
                     "-out", "user.crt"], timeout, out_dir)
        if root is None:
            run_checked([exe, "verify", "-CAfile", "ca.crt", "user.crt"], timeout, out_dir)
        else:
            run_checked([exe, "verify", "-CAfile", "root.crt", "-untrusted", "ca.crt", "user.crt"], timeout, out_dir)
    finally:
        cnf.unlink(missing_ok=True)
    paths = ChainPaths(out_dir)
    pems = [paths["user.crt"], paths["ca.crt"]] + ([paths["root.crt"]] if root is not None else [])
    paths["chain.pem"].write_bytes(b"".join(p.read_bytes() for p in pems))
    return paths
