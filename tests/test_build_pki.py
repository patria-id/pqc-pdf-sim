"""Smoke tests for build_pki (SPEC 4.2)."""
from __future__ import annotations

import csv

import pytest
from asn1crypto import x509 as ax509

from src import build_pki
from src.common.config import load_config
from src.common.pki import FILES, ROOT_FILES, ChainPaths, root_paths
from src.common.x509util import read_der

# one algorithm per family keeps the test fast but covers every code path
SMOKE_ALGS = ["rsa2048", "mldsa44", "slhdsa128f"]


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> tuple[dict, object, object, list[dict]]:
    cfg = load_config("config.yaml")
    base = tmp_path_factory.mktemp("pki")
    certs, results = base / "certs", base / "results"
    rows = build_pki.build_all(cfg, SMOKE_ALGS, certs, results)
    return cfg, certs, results, rows


def test_files_exist(built) -> None:
    cfg, certs, _, _ = built
    rp = root_paths(cfg, certs)
    assert rp.complete() and set(ROOT_FILES) == {p.name for p in rp.directory.iterdir()}
    for aid in SMOKE_ALGS:
        assert ChainPaths(certs / aid).complete(), aid
        assert set(FILES) <= {p.name for p in (certs / aid).iterdir()}


def test_extensions_and_chain(built) -> None:
    cfg, certs, _, _ = built
    for aid in SMOKE_ALGS:
        p = ChainPaths(certs / aid)
        root, ca, user = read_der(p["root.crt"]), read_der(p["ca.crt"]), read_der(p["user.crt"])
        assert root == read_der(root_paths(cfg, certs)["root.crt"])  # one root shared by all algorithms
        assert build_pki.check_extensions(root, True, pathlen=1) == []
        assert build_pki.check_extensions(ca, True) == []
        assert build_pki.check_extensions(user, False) == []
        build_pki.validate_chain(cfg, cfg["algorithms"][aid], p)  # raises on failure
        assert p["chain.pem"].read_bytes().count(b"BEGIN CERTIFICATE") == 3
        root_c, ca_c, user_c = (ax509.Certificate.load(d) for d in (root, ca, user))
        assert ca_c.issuer == root_c.subject and user_c.issuer == ca_c.subject
        assert root_c.public_key.algorithm == "rsa" and root_c.public_key.bit_size == 4096
        assert ax509.Certificate.load(user).subject.native["country_name"] == cfg["cert_profile"]["country"]


def test_tampered_certificate_rejected(built) -> None:
    cfg, certs, _, _ = built
    p = ChainPaths(certs / "mldsa44")
    ca = read_der(p["ca.crt"])
    user = bytearray(read_der(p["user.crt"]))
    user[200] ^= 0x01  # inside TBSCertificate
    from src.common.backend import get_backend
    from src.common.x509util import verify_issued_by

    be = get_backend(cfg, cfg["algorithms"]["mldsa44"]["ca"])
    assert not verify_issued_by(bytes(user), ca, be.verify_spki)


def test_cert_sizes_csv(built) -> None:
    _, _, results, rows = built
    with (results / "cert_sizes.csv").open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == build_pki.CERT_SIZES_COLUMNS
        data = {r["alg"]: r for r in reader}
    assert set(data) == set(SMOKE_ALGS) == {r["alg"] for r in rows}
    for r in data.values():
        assert r["root_alg"] == "RSA-4096"
        assert int(r["chain_der_bytes"]) == (int(r["ca_cert_der_bytes"]) + int(r["user_cert_der_bytes"])
                                             + int(r["root_cert_der_bytes"]))  # pki.embed_root: true
    # PQC certificates are larger than RSA ones
    assert int(data["mldsa44"]["user_cert_der_bytes"]) > int(data["rsa2048"]["user_cert_der_bytes"])


def test_skip_without_force(built) -> None:
    cfg, certs, results, _ = built
    key = certs / "rsa2048" / "user.key"
    before = key.read_bytes()
    build_pki.build_all(cfg, ["rsa2048"], certs, results)
    assert key.read_bytes() == before


def test_new_root_rebuilds_chain(tmp_path) -> None:
    cfg = load_config("config.yaml")
    certs, results = tmp_path / "certs", tmp_path / "results"
    build_pki.build_all(cfg, ["rsa2048"], certs, results)
    old_root = read_der(root_paths(cfg, certs)["root.crt"])
    old_user = (certs / "rsa2048" / "user.key").read_bytes()
    build_pki.build_all(cfg, list(cfg["algorithms"])[:1], certs, results, force=False)
    assert (certs / "rsa2048" / "user.key").read_bytes() == old_user
    import shutil
    shutil.rmtree(root_paths(cfg, certs).directory)  # a new root -> the chain is stale and rebuilt
    build_pki.build_all(cfg, ["rsa2048"], certs, results)
    assert read_der(root_paths(cfg, certs)["root.crt"]) != old_root
    assert (certs / "rsa2048" / "user.key").read_bytes() != old_user
    build_pki.validate_chain(cfg, cfg["algorithms"]["rsa2048"], ChainPaths(certs / "rsa2048"))


def test_same_name_is_der_comparison(built) -> None:
    from src.common.x509util import same_name

    cfg, certs, _, _ = built
    root = ax509.Certificate.load(read_der(root_paths(cfg, certs)["root.crt"]))
    psre = ax509.Certificate.load(read_der(certs / "mldsa44" / "ca.crt"))
    other = ax509.Certificate.load(read_der(certs / "slhdsa128f" / "ca.crt"))
    assert same_name(psre.issuer, root.subject)
    assert not same_name(psre.subject, other.subject)
    assert same_name(psre.issuer, root.subject) == (psre.issuer == root.subject)
