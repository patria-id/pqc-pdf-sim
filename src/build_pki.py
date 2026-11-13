"""Build one simulated PKI (CA + subscriber) per configured algorithm (SPEC 4.2).

Keys and certificates are created with the OpenSSL CLI (setup only; allowed by
CLAUDE.md rule 3). Each chain is then checked in-process with the configured
backend: CA self-signature, subscriber signature by the CA, the subscriber key
matches its certificate, and the required X.509 extensions are present.

Run: ``python -m src.build_pki --config config.yaml [--force] [--only <alg>]``
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
from src.common.pki import ChainPaths, build_chain
from src.common.x509util import read_der, spki_of, verify_issued_by

log = logging.getLogger("build_pki")

CERT_SIZES_COLUMNS = ["alg", "ca_alg", "ca_cert_der_bytes", "user_cert_der_bytes", "chain_der_bytes",
                      "user_pubkey_bytes", "ca_pubkey_bytes"]


def check_extensions(cert_der: bytes, is_ca: bool) -> list[str]:
    """Return a list of problems with the SPEC 4.2 extension profile (empty = OK)."""
    c = ax509.Certificate.load(cert_der)
    problems: list[str] = []
    bc = c.basic_constraints_value
    ku = set(c.key_usage_value.native) if c.key_usage_value else set()
    if bc is None or bool(bc["ca"].native) != is_ca:
        problems.append(f"basicConstraints CA harus {is_ca}")
    if is_ca:
        if bc is not None and bc["path_len_constraint"].native != 0:
            problems.append("pathlen harus 0")
        if not {"key_cert_sign", "crl_sign"} <= ku:
            problems.append(f"keyUsage CA kurang: {sorted(ku)}")
    elif not {"digital_signature", "non_repudiation"} <= ku:
        problems.append(f"keyUsage pemilik kurang: {sorted(ku)}")
    if c.key_identifier_value is None:
        problems.append("SKI tidak ada")
    if c.authority_key_identifier_value is None or c.authority_key_identifier is None:
        problems.append("AKI tidak ada")
    return problems


def validate_chain(cfg: dict[str, Any], spec: dict[str, str], paths: ChainPaths) -> None:
    """In-process checks of a built chain with the configured backend; raises on any problem."""
    sub, ca = spec["subscriber"], spec["ca"]
    be_sub, be_ca = get_backend(cfg, sub), get_backend(cfg, ca)
    if be_ca.verify_spki is None or be_sub.load_private_pem is None:
        raise RuntimeError(f"backend {be_ca.name} tidak mendukung validasi rantai")
    ca_der, user_der = read_der(paths["ca.crt"]), read_der(paths["user.crt"])

    errors: list[str] = []
    if not verify_issued_by(ca_der, ca_der, be_ca.verify_spki):
        errors.append("self-signature CA tidak valid")
    if not verify_issued_by(user_der, ca_der, be_ca.verify_spki):
        errors.append("signature CA atas sertifikat pemilik tidak valid")
    ca_c, user_c = ax509.Certificate.load(ca_der), ax509.Certificate.load(user_der)
    for c, signer in ((ca_c, ca), (user_c, ca)):
        if c["signature_algorithm"]["algorithm"].dotted != sig_oid(signer):
            errors.append(f"OID signature {c.subject.human_friendly}: {c['signature_algorithm']['algorithm'].dotted}")
    if user_c.authority_key_identifier != ca_c.key_identifier:
        errors.append("AKI pemilik != SKI CA")
    errors += [f"CA: {p}" for p in check_extensions(ca_der, True)]
    errors += [f"pemilik: {p}" for p in check_extensions(user_der, False)]

    # the subscriber private key must match the subscriber certificate
    user_key = be_sub.load_private_pem(paths["user.key"].read_bytes())
    msg = os.urandom(32)
    sig = be_sub.sign(user_key, msg)
    if be_sub.verify_spki is None or not be_sub.verify_spki(spki_of(user_der), sig, msg):
        errors.append("user.key tidak cocok dengan user.crt")
    if errors:
        raise RuntimeError("; ".join(errors))


def size_row(alg_id: str, spec: dict[str, str], paths: ChainPaths) -> dict[str, Any]:
    """Row of cert_sizes.csv. Public key sizes are DER SubjectPublicKeyInfo as stored in the certificate."""
    ca_der, user_der = read_der(paths["ca.crt"]), read_der(paths["user.crt"])
    return {
        "alg": alg_id,
        "ca_alg": spec["ca"],
        "ca_cert_der_bytes": len(ca_der),
        "user_cert_der_bytes": len(user_der),
        "chain_der_bytes": len(ca_der) + len(user_der),
        "user_pubkey_bytes": len(spki_of(user_der)),
        "ca_pubkey_bytes": len(spki_of(ca_der)),
    }


def build_all(cfg: dict[str, Any], alg_ids: list[str], certs_dir: Path, results_dir: Path,
              force: bool = False) -> list[dict[str, Any]]:
    """Build missing (or all, with `force`) chains, validate them, rewrite cert_sizes.csv from disk."""
    exe = resolve_openssl_bin(cfg["tools"]["openssl_bin"])
    if exe is None:
        raise FileNotFoundError(f"CLI OpenSSL tidak ditemukan: {cfg['tools']['openssl_bin']}")
    timeout = cli_timeout(cfg)
    names = cfg["pki_names"]
    for aid in alg_ids:
        spec = cfg["algorithms"][aid]
        paths = ChainPaths(certs_dir / aid)
        if paths.complete() and not force:
            log.info("%s: sertifikat sudah ada, dilewati (pakai --force untuk membuat ulang)", aid)
        else:
            if paths.directory.exists():
                shutil.rmtree(paths.directory)
            fmt = {"alg_id": aid, "subscriber": spec["subscriber"], "ca": spec["ca"]}
            log.info("%s: membuat CA %s dan pemilik %s ...", aid, spec["ca"], spec["subscriber"])
            build_chain(exe, spec["subscriber"], spec["ca"], cfg, paths.directory, timeout,
                        names["ca_cn"].format(**fmt), names["user_cn"].format(**fmt))
        validate_chain(cfg, spec, paths)
        log.info("%s: rantai valid", aid)
    rows = [size_row(aid, cfg["algorithms"][aid], ChainPaths(certs_dir / aid))
            for aid in cfg["algorithms"] if ChainPaths(certs_dir / aid).complete()]
    write_csv(results_dir / "cert_sizes.csv", CERT_SIZES_COLUMNS, rows)
    return rows


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = base_arg_parser("Membangun PKI simulasi per algoritma (SPEC 4.2)")
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
