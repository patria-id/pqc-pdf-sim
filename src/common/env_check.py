"""Stage 0: environment check and CMS spike for PQC signatures.

Checks which backend can run each configured algorithm in-process, whether
CMS SignedData with ML-DSA / SLH-DSA is supported natively (cryptography API,
OpenSSL CLI), and whether the asn1crypto fallback (RFC 5652 SignedData
assembled by hand, signature made by the backend) works. Findings are written
to ``results/env_report.json``.

Run: ``python -m src.common.env_check --config config.yaml``
Exit code 0 = every algorithm runs on the configured backend and has a proven
CMS path, 2 = blockers found (see report), 1 = unexpected error.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import platform
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from src.common.backend import (
    BACKEND_NAMES, Backend, cryptography_backend, libcrypto_info, liboqs_info, make_backend,
)
from src.common.cms import build_cms_asn1, verify_cms_asn1
from src.common.config import base_arg_parser, load_config, resolve_path
from src.common.opensslcli import cli_timeout, genpkey_args, openssl_cli_info, run_cmd
from src.common.pki import build_chain
from src.common.util import parse_version, pkg_version, short_err
from src.common.x509util import read_der, spki_of, verify_issued_by

log = logging.getLogger("env_check")

LIBS = [
    "cryptography", "asn1crypto", "pyhanko", "pyhanko-certvalidator", "pikepdf",
    "pypdf", "psutil", "pyyaml", "reportlab", "pillow", "pandas", "matplotlib", "scipy",
    "pytest", "liboqs-python",
]


# --------------------------------------------------------------------------- OpenSSL
def cryptography_openssl() -> dict[str, Any]:
    """OpenSSL version statically bundled in the `cryptography` wheel."""
    from cryptography.hazmat.backends.openssl import backend

    text = backend.openssl_version_text()
    return {"library": "cryptography", "library_version": pkg_version("cryptography"),
            "openssl_version_text": text, "openssl_version": ".".join(map(str, parse_version(text)))}



# --------------------------------------------------------------------------- backends
def probe_algorithm(alg: str, ctx: dict[str, Any], preferred: str) -> tuple[dict[str, Any], Backend | None]:
    """Probe every backend; select `preferred` if it works, otherwise the first working one."""
    rec: dict[str, Any] = {"candidates": {}, "selected_backend": None}
    working: dict[str, Backend] = {}
    for label in BACKEND_NAMES:
        try:
            be = make_backend(label, alg, ctx)
            key = be.generate()
            msg = os.urandom(32)
            sig = be.sign(key, msg)
            ok = be.verify(key, sig, msg)
            bad = be.verify(key, sig, bytes([msg[0] ^ 1]) + msg[1:])
            rec["candidates"][label] = {"ok": ok and not bad, "version": be.version,
                                        "signature_bytes": len(sig), "public_key_bytes": len(be.public_bytes(key))}
            if ok and not bad:
                working[label] = be
        except Exception as exc:  # noqa: BLE001
            rec["candidates"][label] = {"ok": False, "error": short_err(exc)}
    order = [preferred] + [b for b in BACKEND_NAMES if b != preferred]
    label = next((b for b in order if b in working), None)
    if label is None:
        return rec, None
    c = rec["candidates"][label]
    rec.update(selected_backend=label, backend_version=c["version"], signature_bytes=c["signature_bytes"],
               public_key_bytes=c["public_key_bytes"], is_preferred=(label == preferred))
    return rec, working[label]


# --------------------------------------------------------------------------- spike: certificates
def make_cert(subject_cn: str, pub_key: Any, issuer_cn: str, issuer_key: Any, is_ca: bool,
              cfg: dict[str, Any]) -> Any:
    """Throwaway certificate via cryptography's X.509 builder (spike only)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    prof = cfg["cert_profile"]

    def name(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, prof["country"]),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, prof["organization"]),
                          x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    now = dt.datetime.now(dt.timezone.utc)
    algo = hashes.SHA256() if isinstance(issuer_key, rsa.RSAPrivateKey) else None
    return (x509.CertificateBuilder().subject_name(name(subject_cn)).issuer_name(name(issuer_cn))
            .public_key(pub_key).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True)
            .sign(issuer_key, algo))


# --------------------------------------------------------------------------- spike: CMS
def cms_native_cryptography(alg: str, ca_alg: str, data: bytes, cfg: dict[str, Any]) -> dict[str, Any]:
    """Try cryptography's PKCS7SignatureBuilder (detached, DER) with cryptography keys."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7

    try:
        be, be_ca = cryptography_backend(alg), cryptography_backend(ca_alg)
    except NotImplementedError as exc:
        return {"supported": False, "error": short_err(exc)}
    try:
        ca_key, key = be_ca.generate(), be.generate()
        ca = make_cert("Spike CA", ca_key.public_key(), "Spike CA", ca_key, True, cfg)
        cert = make_cert("Spike User", key.public_key(), "Spike CA", ca_key, False, cfg)
        der = (pkcs7.PKCS7SignatureBuilder().set_data(data).add_signer(cert, key, hashes.SHA256())
               .sign(serialization.Encoding.DER,
                     [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]))
        res = verify_cms_asn1(der, data, None)
        return {"supported": True, "cms_bytes": len(der), "digest_ok": res["digest_ok"],
                "ca_ok": bool(ca)}
    except Exception as exc:  # noqa: BLE001
        return {"supported": False, "error": short_err(exc)}


def cms_native_openssl_cli(cli: dict[str, Any], alg: str, timeout: int) -> dict[str, Any]:
    """Try `openssl cms -sign/-verify` with a fresh key (setup-style check, not timed)."""
    if not cli.get("path") or not cli.get("meets_min") or not cli["sig_algs"].get(alg):
        return {"supported": False, "skipped": True,
                "reason": f"CLI OpenSSL tidak memenuhi syarat ({cli.get('version_text') or 'tidak ditemukan'})"}
    exe = cli["path"]
    with tempfile.TemporaryDirectory() as tmp:
        steps = [
            [exe, "genpkey", *genpkey_args(alg), "-out", "k.pem"],
            [exe, "req", "-new", "-x509", "-key", "k.pem", "-out", "c.pem", "-days", "1", "-subj", "/CN=spike"],
            [exe, "cms", "-sign", "-binary", "-in", "d.bin", "-signer", "c.pem", "-inkey", "k.pem",
             "-md", "sha256", "-outform", "DER", "-out", "s.der"],
            [exe, "cms", "-verify", "-binary", "-inform", "DER", "-in", "s.der", "-content", "d.bin",
             "-CAfile", "c.pem", "-purpose", "any", "-out", os.devnull],
        ]
        Path(tmp, "d.bin").write_bytes(os.urandom(1024))
        for cmd in steps:
            p = run_cmd(cmd, timeout, cwd=tmp)
            if p.returncode != 0:
                return {"supported": False, "failed_step": " ".join(cmd[1:3]),
                        "error": (p.stderr or p.stdout).strip()[:300]}
        info = verify_cms_asn1(Path(tmp, "s.der").read_bytes(), Path(tmp, "d.bin").read_bytes(), None)
        return {"supported": True, "cms_bytes": Path(tmp, "s.der").stat().st_size, "verify_ok": True,
                "digest_alg": info["digest_alg"], "signature_alg": info["signature_alg"],
                "signed_attrs": info["signed_attrs"]}


def cert_verifier(backend: Backend) -> Callable[[bytes, bytes, bytes], bool]:
    """Signature verifier that takes the public key from a DER certificate."""
    if backend.verify_spki is None:
        raise NotImplementedError(f"backend {backend.name} tidak bisa verifikasi dari SPKI")
    vs = backend.verify_spki
    return lambda cert_der, sig, msg: vs(spki_of(cert_der), sig, msg)


def spike_algorithm(alg_id: str, spec: dict[str, str], backends: dict[str, Backend | None],
                    cli: dict[str, Any], cfg: dict[str, Any], timeout: int) -> dict[str, Any]:
    """CMS spike for one configured algorithm: native (cryptography, OpenSSL CLI) then asn1crypto fallback."""
    from cryptography.hazmat.primitives import serialization

    sub, ca = spec["subscriber"], spec["ca"]
    data = os.urandom(4096)
    res: dict[str, Any] = {"alg": alg_id, "subscriber": sub, "ca": ca,
                           "native_cryptography": cms_native_cryptography(sub, ca, data, cfg),
                           "native_openssl_cli": cms_native_openssl_cli(cli, sub, timeout)}
    be_sub, be_ca = backends.get(sub), backends.get(ca)
    if be_sub is None or be_ca is None:
        missing = [n for n, b in ((sub, be_sub), (ca, be_ca)) if b is None]
        res["fallback_asn1crypto"] = {"ok": False, "skipped": True,
                                      "reason": f"tidak ada backend in-process untuk {', '.join(missing)}"}
        return res

    try:
        if be_sub.x509_native and be_ca.x509_native:
            cert_source = "cryptography X.509 builder"
            ca_key, user_key = be_ca.generate(), be_sub.generate()
            der = serialization.Encoding.DER
            ca_der = make_cert("Spike CA", ca_key.public_key(), "Spike CA", ca_key, True, cfg).public_bytes(der)
            user_der = make_cert("Spike User", user_key.public_key(), "Spike CA", ca_key, False,
                                 cfg).public_bytes(der)
        else:
            if not (cli.get("meets_min") and cli["sig_algs"].get(sub) and cli["sig_algs"].get(ca)):
                raise NotImplementedError("butuh CLI OpenSSL >= 3.5 untuk membuat sertifikat")
            if be_sub.load_private_pem is None:
                raise NotImplementedError(f"backend {be_sub.name} tidak bisa memuat kunci PEM")
            cert_source = "openssl CLI"
            with tempfile.TemporaryDirectory() as tmp:
                ch = build_chain(cli["path"], sub, ca, cfg, Path(tmp), timeout, "Spike CA", "Spike User",
                                 ca_days=1, user_days=1)
                user_key = be_sub.load_private_pem(ch["user.key"].read_bytes())
                ca_der, user_der = read_der(ch["ca.crt"]), read_der(ch["user.crt"])
        if be_ca.verify_spki is None:
            raise NotImplementedError(f"backend {be_ca.name} tidak bisa verifikasi dari SPKI")
        chain_ok = verify_issued_by(user_der, ca_der, be_ca.verify_spki)
        cms_der = build_cms_asn1(data, sub, be_sub, user_key, user_der, [ca_der])
        verifier = cert_verifier(be_sub)
        good = verify_cms_asn1(cms_der, data, verifier)
        tampered = bytearray(data)
        tampered[len(tampered) // 2] ^= 0x01
        bad = verify_cms_asn1(cms_der, bytes(tampered), verifier)
        res["fallback_asn1crypto"] = {
            "ok": bool(good["valid"] and not bad["valid"] and chain_ok),
            "backend": be_sub.name, "cert_source": cert_source,
            "cms_bytes": len(cms_der), "chain_ok": chain_ok, "verify": good,
            "tampered_content_rejected": not bad["valid"],
        }
    except Exception as exc:  # noqa: BLE001
        res["fallback_asn1crypto"] = {"ok": False, "error": short_err(exc)}
    return res


# --------------------------------------------------------------------------- main
def run(cfg: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Run all checks; return (report, exit_code)."""
    ec = cfg.get("env_check", {})
    tools = cfg.get("tools", {})
    preferred = cfg.get("crypto_backend", "openssl-ctypes")
    timeout = cli_timeout(cfg)
    min_ver = parse_version(str(ec.get("min_openssl", "3.5.0")))
    algs: dict[str, dict[str, str]] = cfg["algorithms"]
    names = sorted({a["subscriber"] for a in algs.values()} | {a["ca"] for a in algs.values()})

    import ssl

    log.info("Cek OpenSSL ...")
    cli = openssl_cli_info(tools.get("openssl_bin", "openssl"), names, min_ver, timeout)
    crypto_ossl = cryptography_openssl()
    lc = libcrypto_info(tools.get("libcrypto_path"), cli.get("path"), min_ver)
    log.info("Cek liboqs-python ...")
    oqs_info = liboqs_info(tools.get("liboqs_install_path"), timeout)
    ctx = {"libcrypto": lc, "liboqs": oqs_info}

    log.info("Uji backend per algoritma (keygen/sign/verify in-process), preferensi=%s ...", preferred)
    probes: dict[str, Any] = {}
    backends: dict[str, Backend | None] = {}
    for n in names:
        probes[n], backends[n] = probe_algorithm(n, ctx, preferred)
        probes[n]["openssl_cli_has_alg"] = bool(cli["sig_algs"].get(n)) and cli["meets_min"]
        log.info("  %-20s backend=%s", n, probes[n]["selected_backend"])

    log.info("Spike CMS SignedData (detached) ...")
    spikes = {a: spike_algorithm(a, algs[a], backends, cli, cfg, timeout)
              for a in ec.get("spike_algorithms", [])}

    per_alg: dict[str, Any] = {}
    blockers: list[str] = []
    for aid, spec in algs.items():
        sub, ca = spec["subscriber"], spec["ca"]
        entry: dict[str, Any] = {
            "subscriber": sub, "ca": ca,
            "subscriber_backend": probes[sub]["selected_backend"],
            "ca_backend": probes[ca]["selected_backend"],
            "certs_via": ("openssl CLI" if probes[sub]["openssl_cli_has_alg"] and probes[ca]["openssl_cli_has_alg"]
                          else None),
        }
        sp = spikes.get(aid)
        if sp is None:  # not spiked: inherit the result of a spiked algorithm of the same family
            sp = next((s for k, s in spikes.items() if algs[k]["family"] == spec["family"]), None)
            entry["cms_evidence_from"] = sp["alg"] if sp else None
        else:
            entry["cms_evidence_from"] = aid
        if sp:
            entry["cms_native_in_process"] = bool(sp["native_cryptography"].get("supported"))
            entry["cms_native_cli"] = bool(sp["native_openssl_cli"].get("supported"))
            entry["cms_fallback_asn1crypto"] = bool(sp["fallback_asn1crypto"].get("ok"))
        elif spec["family"] == "rsa":
            entry["cms_native_in_process"] = True  # RSA: cryptography/pyHanko builder
        if entry.get("cms_fallback_asn1crypto") and entry["subscriber_backend"]:
            entry["cms_path"] = "asn1crypto + " + entry["subscriber_backend"]
        elif entry.get("cms_native_in_process"):
            entry["cms_path"] = "cryptography/pyHanko (native)"
        else:
            entry["cms_path"] = None
        per_alg[aid] = entry

        for role, n, key in (("pemilik", sub, "subscriber_backend"), ("CA", ca, "ca_backend")):
            if entry[key] is None:
                blockers.append(f"{aid}: tidak ada backend in-process untuk {n} ({role})")
            elif entry[key] != preferred:
                blockers.append(f"{aid}: {n} tidak bisa memakai backend '{preferred}' (pakai {entry[key]})")
        if entry["cms_path"] is None:
            blockers.append(f"{aid}: belum ada jalur CMS yang terbukti")
        if entry["certs_via"] is None and entry["subscriber_backend"] != "cryptography":
            blockers.append(f"{aid}: tidak ada cara membuat sertifikat (CLI OpenSSL >= 3.5)")
    blockers = sorted(set(blockers))

    selected = {p["selected_backend"] for p in probes.values()}
    lc_public = {k: v for k, v in lc.items() if not k.startswith("_")}
    report = {
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "config": cfg["_config_path"],
        "python": {"version": sys.version.split()[0], "executable": sys.executable,
                   "ssl_module_openssl": ssl.OPENSSL_VERSION},
        "platform": {"system": platform.system(), "release": platform.release(),
                     "version": platform.version(), "machine": platform.machine(),
                     "processor": platform.processor()},
        "openssl": {"min_required": ".".join(map(str, min_ver)), "cli": cli, "libcrypto_ctypes": lc_public,
                    "cryptography_bundled": crypto_ossl},
        "liboqs": oqs_info,
        "libraries": {lib: pkg_version(lib) for lib in LIBS},
        "backend_preference": preferred,
        "backend_uniform": len(selected) == 1 and None not in selected,
        "algorithm_probes": probes,
        "cms_spike": spikes,
        "per_algorithm": per_alg,
        "cms_pqc_native": {a: {"in_process_api": e.get("cms_native_in_process"), "openssl_cli": e.get("cms_native_cli")}
                           for a, e in per_alg.items() if algs[a]["family"] != "rsa"},
        "blockers": blockers,
        "status": "OK" if not blockers else "BLOCKED",
    }
    return report, (0 if not blockers else 2)


def print_summary(report: dict[str, Any]) -> None:
    """Human-readable summary (Indonesian)."""
    o = report["openssl"]
    print("\n=== Ringkasan env_check ===")
    print(f"Python            : {report['python']['version']} ({report['python']['executable']})")
    print(f"OpenSSL CLI       : {o['cli'].get('version_text') or 'tidak ditemukan'}"
          f"  -> memenuhi >= {o['min_required']}: {o['cli']['meets_min']}")
    print(f"libcrypto (ctypes): {o['libcrypto_ctypes'].get('version_text') or o['libcrypto_ctypes'].get('error')}"
          f"  [{o['libcrypto_ctypes'].get('path')}]")
    print(f"OpenSSL (cryptography {o['cryptography_bundled']['library_version']}): "
          f"{o['cryptography_bundled']['openssl_version_text']}")
    lo = report["liboqs"]
    print(f"liboqs-python     : {lo['python_package'] or 'tidak terpasang'}; native lib: {lo['native_lib'] or '-'}")
    print(f"\nBackend per algoritma (preferensi: {report['backend_preference']}, "
          f"seragam: {report['backend_uniform']}):")
    for n, p in report["algorithm_probes"].items():
        cands = ", ".join(f"{k}={'ok' if v['ok'] else 'x'}" for k, v in p["candidates"].items())
        if p["selected_backend"]:
            print(f"  {n:<20} {p['selected_backend']:<15} sig={p['signature_bytes']:>6} B  "
                  f"pub={p['public_key_bytes']:>5} B  [{cands}]")
        else:
            print(f"  {n:<20} {'TIDAK ADA':<15} [{cands}]")
    print("\nSpike CMS:")
    for a, s in report["cms_spike"].items():
        pad = " " * len(a)
        nc, cl, fb = s["native_cryptography"], s["native_openssl_cli"], s["fallback_asn1crypto"]
        print(f"  {a}: native API cryptography = {nc.get('supported')} ({nc.get('error') or 'ok'})")
        cl_note = cl.get("error") or cl.get("reason") or f"cms={cl.get('cms_bytes')} B, sigalg {cl.get('signature_alg')}"
        print(f"  {pad}  native openssl CLI      = {cl.get('supported')} ({cl_note})")
        fb_note = fb.get("error") or fb.get("reason") or (
            f"cms={fb.get('cms_bytes')} B, backend {fb.get('backend')}, sertifikat via {fb.get('cert_source')}, "
            f"rantai ok={fb.get('chain_ok')}, konten diubah ditolak={fb.get('tampered_content_rejected')}")
        print(f"  {pad}  fallback asn1crypto     = {fb.get('ok')} ({fb_note})")
    print("\nJalur per algoritma:")
    for a, e in report["per_algorithm"].items():
        print(f"  {a:<11} pemilik={e['subscriber_backend']}, CA={e['ca_backend']}, "
              f"sertifikat={e['certs_via']}, CMS={e['cms_path']}")
    print(f"\nStatus: {report['status']}")
    for b in report["blockers"]:
        print(f"  - {b}")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = base_arg_parser("Tahap 0: cek lingkungan dan spike CMS PQC")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    report, code = run(cfg)
    out = resolve_path(cfg, "results") / "env_report.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print_summary(report)
    log.info("Laporan ditulis ke %s", out)
    return code


if __name__ == "__main__":
    sys.exit(main())
