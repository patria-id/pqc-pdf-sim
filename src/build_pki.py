"""Build the simulated three-level PKI (SPEC 4.2): Root CA -> PSrE -> subscriber.

One root CA (``pki.root_alg``) is shared by every algorithm, as in Indonesia where the
root CA issues the certificates of all PSrE. Each configured algorithm gets its own
PSrE (``algorithms.<id>.ca``) and subscriber (``algorithms.<id>.subscriber``).

Keys and certificates are created with the OpenSSL CLI (setup only; allowed by
CLAUDE.md rule 3). Each chain is then checked in-process with the configured
backend: root self-signature, PSrE signed by the root, subscriber signed by the
PSrE, signature OIDs, SKI/AKI links, the subscriber key matches its certificate,
and the required X.509 extensions are present.

Run: ``python -m src.build_pki --config config.yaml [--force] [--only <alg>]``
(``--force`` without ``--only`` also rebuilds the root; chains issued by an older
root are always rebuilt.)
"""
from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from asn1crypto import x509 as ax509

from src.common.backend import get_backend
from src.common.config import base_arg_parser, load_config, resolve_path
from src.common.csvio import write_csv
from src.common.oids import sig_oid
from src.common.opensslcli import cli_timeout, resolve_openssl_bin
from src.common.pki import ChainPaths, build_chain, build_root, embedded_certs, root_paths
from src.common.x509util import read_der, spki_of, verify_issued_by

log = logging.getLogger("build_pki")

CERT_SIZES_COLUMNS = ["alg", "ca_alg", "ca_cert_der_bytes", "user_cert_der_bytes", "chain_der_bytes",
                      "user_pubkey_bytes", "ca_pubkey_bytes", "root_alg", "root_cert_der_bytes",
                      "root_pubkey_bytes"]


def check_extensions(cert_der: bytes, is_ca: bool, pathlen: int = 0) -> list[str]:
    """Return a list of problems with the SPEC 4.2 extension profile (empty = OK)."""
    c = ax509.Certificate.load(cert_der)
    problems: list[str] = []
    bc = c.basic_constraints_value
    ku = set(c.key_usage_value.native) if c.key_usage_value else set()
    if bc is None or bool(bc["ca"].native) != is_ca:
        problems.append(f"basicConstraints CA harus {is_ca}")
    if is_ca:
        if bc is not None and bc["path_len_constraint"].native != pathlen:
            problems.append(f"pathlen harus {pathlen}")
        if not {"key_cert_sign", "crl_sign"} <= ku:
            problems.append(f"keyUsage CA kurang: {sorted(ku)}")
    elif not {"digital_signature", "non_repudiation"} <= ku:
        problems.append(f"keyUsage pemilik kurang: {sorted(ku)}")
    if c.key_identifier_value is None:
        problems.append("SKI tidak ada")
    if c.authority_key_identifier_value is None or c.authority_key_identifier is None:
        problems.append("AKI tidak ada")
    return problems


def _verifier(cfg: dict[str, Any], alg: str) -> Any:
    be = get_backend(cfg, alg)
    if be.verify_spki is None:
        raise RuntimeError(f"backend {be.name} tidak mendukung verifikasi dari SPKI")
    return be.verify_spki


def validate_root(cfg: dict[str, Any], root_der: bytes) -> None:
    """In-process checks of the shared root certificate; raises on any problem."""
    root_alg = cfg["pki"]["root_alg"]
    errors: list[str] = []
    if not verify_issued_by(root_der, root_der, _verifier(cfg, root_alg)):
        errors.append("self-signature Root tidak valid")
    c = ax509.Certificate.load(root_der)
    if c["signature_algorithm"]["algorithm"].dotted != sig_oid(root_alg):
        errors.append(f"OID signature Root: {c['signature_algorithm']['algorithm'].dotted}")
    errors += [f"Root: {p}" for p in check_extensions(root_der, True, pathlen=1)]
    if errors:
        raise RuntimeError("; ".join(errors))


def validate_chain(cfg: dict[str, Any], spec: dict[str, str], paths: ChainPaths,
                   root_der: bytes | None = None) -> None:
    """In-process checks of a built Root -> PSrE -> subscriber chain; raises on any problem.

    `root_der` is the shared root certificate; defaults to the copy in the chain folder.
    """
    sub, ca, root_alg = spec["subscriber"], spec["ca"], cfg["pki"]["root_alg"]
    be_sub = get_backend(cfg, sub)
    if be_sub.load_private_pem is None or be_sub.verify_spki is None:
        raise RuntimeError(f"backend {be_sub.name} tidak mendukung kunci PEM / verifikasi SPKI")
    root_copy = read_der(paths["root.crt"])
    root_der = root_copy if root_der is None else root_der
    ca_der, user_der = read_der(paths["ca.crt"]), read_der(paths["user.crt"])

    errors: list[str] = []
    if root_copy != root_der:
        errors.append("root.crt di folder rantai berbeda dengan Root bersama")
    if not verify_issued_by(ca_der, root_der, _verifier(cfg, root_alg)):
        errors.append("signature Root atas sertifikat PSrE tidak valid")
    if not verify_issued_by(user_der, ca_der, _verifier(cfg, ca)):
        errors.append("signature PSrE atas sertifikat pemilik tidak valid")
    root_c, ca_c, user_c = (ax509.Certificate.load(d) for d in (root_der, ca_der, user_der))
    for c, signer in ((ca_c, root_alg), (user_c, ca)):
        if c["signature_algorithm"]["algorithm"].dotted != sig_oid(signer):
            errors.append(f"OID signature {c.subject.human_friendly}: {c['signature_algorithm']['algorithm'].dotted}")
    if ca_c.authority_key_identifier != root_c.key_identifier:
        errors.append("AKI PSrE != SKI Root")
    if user_c.authority_key_identifier != ca_c.key_identifier:
        errors.append("AKI pemilik != SKI PSrE")
    errors += [f"PSrE: {p}" for p in check_extensions(ca_der, True, pathlen=0)]
    errors += [f"pemilik: {p}" for p in check_extensions(user_der, False)]

    # the subscriber private key must match the subscriber certificate
    user_key = be_sub.load_private_pem(paths["user.key"].read_bytes())
    msg = os.urandom(32)
    if not be_sub.verify_spki(spki_of(user_der), be_sub.sign(user_key, msg), msg):
        errors.append("user.key tidak cocok dengan user.crt")
    if errors:
        raise RuntimeError("; ".join(errors))


def size_row(cfg: dict[str, Any], alg_id: str, paths: ChainPaths) -> dict[str, Any]:
    """Row of cert_sizes.csv.

    ``chain_der_bytes`` = all certificates embedded in the CMS (subscriber + PSrE, plus the
    root when ``pki.embed_root``). Public key sizes are DER SubjectPublicKeyInfo.
    """
    spec = cfg["algorithms"][alg_id]
    root_der, ca_der, user_der = (read_der(paths[f]) for f in ("root.crt", "ca.crt", "user.crt"))
    return {
        "alg": alg_id,
        "ca_alg": spec["ca"],
        "ca_cert_der_bytes": len(ca_der),
        "user_cert_der_bytes": len(user_der),
        "chain_der_bytes": len(user_der) + sum(len(d) for d in embedded_certs(cfg, paths)),
        "user_pubkey_bytes": len(spki_of(user_der)),
        "ca_pubkey_bytes": len(spki_of(ca_der)),
        "root_alg": cfg["pki"]["root_alg"],
        "root_cert_der_bytes": len(root_der),
        "root_pubkey_bytes": len(spki_of(root_der)),
    }


def ensure_root(cfg: dict[str, Any], exe: str, certs_dir: Path, timeout: int, force: bool) -> bytes:
    """Build the shared root if missing (or with `force`), validate it, return its DER."""
    rp = root_paths(cfg, certs_dir)
    root_alg = cfg["pki"]["root_alg"]
    if rp.complete() and not force:
        log.info("Root CA %s: sudah ada, dipakai ulang", root_alg)
    else:
        if rp.directory.exists():
            shutil.rmtree(rp.directory)
        log.info("Root CA %s: membuat ...", root_alg)
        build_root(exe, root_alg, cfg, rp.directory, timeout, cfg["pki_names"]["root_cn"].format(root=root_alg))
    root_der = read_der(rp["root.crt"])
    validate_root(cfg, root_der)
    return root_der


def build_all(cfg: dict[str, Any], alg_ids: list[str], certs_dir: Path, results_dir: Path,
              force: bool = False) -> list[dict[str, Any]]:
    """Build the root and missing (or all, with `force`) chains, validate them, rewrite cert_sizes.csv.

    The root is rebuilt only by `force` covering every configured algorithm; a chain whose
    root.crt differs from the shared root is always rebuilt.
    """
    exe = resolve_openssl_bin(cfg["tools"]["openssl_bin"])
    if exe is None:
        raise FileNotFoundError(f"CLI OpenSSL tidak ditemukan: {cfg['tools']['openssl_bin']}")
    timeout = cli_timeout(cfg)
    names = cfg["pki_names"]
    root_alg = cfg["pki"]["root_alg"]
    root_der = ensure_root(cfg, exe, certs_dir, timeout, force and set(alg_ids) >= set(cfg["algorithms"]))
    rp = root_paths(cfg, certs_dir)
    for aid in alg_ids:
        spec = cfg["algorithms"][aid]
        paths = ChainPaths(certs_dir / aid)
        stale = paths.complete() and read_der(paths["root.crt"]) != root_der
        if paths.complete() and not force and not stale:
            log.info("%s: sertifikat sudah ada, dilewati (pakai --force untuk membuat ulang)", aid)
        else:
            if stale:
                log.info("%s: rantai diterbitkan Root lama, dibuat ulang", aid)
            if paths.directory.exists():
                shutil.rmtree(paths.directory)
            fmt = {"alg_id": aid, "subscriber": spec["subscriber"], "ca": spec["ca"], "root": root_alg}
            log.info("%s: membuat PSrE %s dan pemilik %s di bawah Root %s ...",
                     aid, spec["ca"], spec["subscriber"], root_alg)
            build_chain(exe, spec["subscriber"], spec["ca"], cfg, paths.directory, timeout,
                        names["ca_cn"].format(**fmt), names["user_cn"].format(**fmt), root=(rp, root_alg))
        validate_chain(cfg, spec, paths, root_der)
        log.info("%s: rantai valid (Root -> PSrE -> pemilik)", aid)
    rows = []
    for aid in cfg["algorithms"]:
        paths = ChainPaths(certs_dir / aid)
        if not paths.complete():
            continue
        if read_der(paths["root.crt"]) != root_der:
            log.warning("%s: rantai diterbitkan Root lama, tidak dimasukkan ke cert_sizes.csv", aid)
            continue
        rows.append(size_row(cfg, aid, paths))
    write_csv(results_dir / "cert_sizes.csv", CERT_SIZES_COLUMNS, rows)
    return rows


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = base_arg_parser("Membangun PKI simulasi 3 level: Root -> PSrE -> pemilik (SPEC 4.2)")
    ap.add_argument("--force", action="store_true", help="buat ulang walau sertifikat sudah ada")
    ap.add_argument("--only", choices=None, help="hanya satu ID algoritma dari config")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    if args.only and args.only not in cfg["algorithms"]:
        ap.error(f"--only harus salah satu dari: {', '.join(cfg['algorithms'])}")
    alg_ids = [args.only] if args.only else list(cfg["algorithms"])
    build_all(cfg, alg_ids, resolve_path(cfg, "certs"), resolve_path(cfg, "results"), args.force)
    return 0


if __name__ == "__main__":
    sys.exit(main())
