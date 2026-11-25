#!/usr/bin/env python3
"""
tests/e2e/harness/generate_fixtures.py
Generates comprehensive synthetic and adversarial test DAR fixtures for E2E testing.
Covers Tiers 1-4 including AT-A01, AT-A02, AT-A04, AT-A06, and AT-A08 invariants.
"""

import hashlib
import io
import os
import struct
import sys
import zipfile

def encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    if value < 0:
        # 64-bit two's complement for negative numbers
        value = (1 << 64) + value
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)

def encode_tag(field_number: int, wire_type: int) -> bytes:
    return encode_varint((field_number << 3) | wire_type)

def encode_bytes_field(field_number: int, data: bytes) -> bytes:
    return encode_tag(field_number, 2) + encode_varint(len(data)) + data

def encode_str_field(field_number: int, s: str) -> bytes:
    b = s.encode('utf-8')
    return encode_tag(field_number, 2) + encode_varint(len(b)) + b

def encode_varint_field(field_number: int, value: int) -> bytes:
    return encode_tag(field_number, 0) + encode_varint(value)

def build_dotted_name(segments_interned_str: list) -> bytes:
    """Encode DottedName message: repeated int32 segments_interned_str = 1"""
    # Packed varints for repeated int32
    packed = b"".join(encode_varint(s) for s in segments_interned_str)
    return encode_bytes_field(1, packed)

def build_module(name_interned_dname: int) -> bytes:
    """Encode Module message: int32 name_interned_dname = 1 (an index into interned_dotted_names).

    This is the layout of the official daml_lf2.proto. Earlier versions of this generator wrote the name as a
    nested DottedName message, a layout that no real package has (S-PROTO-002).
    """
    return encode_varint_field(1, name_interned_dname)

def build_package_metadata(name_interned_str: int, version_interned_str: int) -> bytes:
    """Encode PackageMetadata: int32 name_interned_str = 1, int32 version_interned_str = 2"""
    out = bytearray()
    out.extend(encode_varint_field(1, name_interned_str))
    out.extend(encode_varint_field(2, version_interned_str))
    return bytes(out)

def build_package_lf2(package_name="sample-contract",
                      package_version="0.1.0",
                      modules=None,
                      oob_name_idx=None) -> bytes:
    """
    Encode daml_lf_2.Package protobuf message:
    repeated Module modules = 1;
    PackageMetadata metadata = 2;
    repeated Module modules = 1;
    repeated string interned_strings = 2;
    repeated DottedName interned_dotted_names = 3;
    PackageMetadata metadata = 4;
    """
    if modules is None:
        modules = ["AssetHolding"]

    # In real Daml 3.x, interned strings list contains modules first, then package metadata
    interned_strings = list(modules)
    name_idx = len(interned_strings)
    interned_strings.append(package_name)
    ver_idx = len(interned_strings)
    interned_strings.append(package_version)

    if oob_name_idx is not None:
        name_idx = oob_name_idx

    meta_bytes = build_package_metadata(name_idx, ver_idx)

    mod_messages = []
    for idx, _ in enumerate(modules):
        mod_bytes = build_module(idx)
        mod_messages.append(mod_bytes)

    out = bytearray()
    # Field 1: modules
    for m in mod_messages:
        out.extend(encode_bytes_field(1, m))

    # Field 2: interned_strings
    for s in interned_strings:
        out.extend(encode_str_field(2, s))

    # Field 3: interned_dotted_names
    for idx, _ in enumerate(modules):
        dname = build_dotted_name([idx])
        out.extend(encode_bytes_field(3, dname))

    # Field 4: metadata
    out.extend(encode_bytes_field(4, meta_bytes))

    return bytes(out)

def build_archive_payload(minor="1",
                          sum_type="lf2",
                          package_bytes=b"") -> bytes:
    """
    Encode ArchivePayload protobuf message (official daml_lf.proto, S-PROTO-002):
    daml_lf_1 = 2 (bytes)
    daml_lf_2 = 4 (bytes)
    minor = 3 (string)
    Earlier versions of this generator wrote the LF 1 payload as field 1, a tag the official schema does not have.
    """
    out = bytearray()
    if sum_type == "lf1":
        out.extend(encode_bytes_field(2, package_bytes))
    elif sum_type == "lf2":
        # Wire tag 4 is standard in Daml 3.x
        out.extend(encode_bytes_field(4, package_bytes))
    out.extend(encode_str_field(3, minor))
    return bytes(out)

def build_archive(payload_bytes: bytes,
                  hash_func=0,
                  override_hash=None) -> bytes:
    """
    Encode Archive protobuf message:
    HashFunction hash_function = 1 (SHA256 = 0)
    bytes payload = 3
    string hash = 4 (hex lowercase sha256)
    """
    if override_hash is not None:
        hash_str = override_hash
    else:
        hash_str = hashlib.sha256(payload_bytes).hexdigest().lower()

    out = bytearray()
    out.extend(encode_varint_field(1, hash_func))
    out.extend(encode_bytes_field(3, payload_bytes))
    out.extend(encode_str_field(4, hash_str))
    return bytes(out)

def create_dalf(minor="1",
                package_name="sample-contract",
                package_version="0.1.0",
                modules=None,
                sum_type="lf2",
                hash_func=0,
                tamper_payload=False,
                override_hash=None,
                oob_name_idx=None) -> bytes:
    pkg = build_package_lf2(package_name, package_version, modules, oob_name_idx=oob_name_idx)
    payload = build_archive_payload(minor=minor, sum_type=sum_type, package_bytes=pkg)

    if tamper_payload:
        # Compute valid hash first, then mutate payload
        valid_hash = hashlib.sha256(payload).hexdigest().lower()
        tampered_payload = bytearray(payload)
        tampered_payload[len(tampered_payload) // 2] ^= 0xFF
        return build_archive(bytes(tampered_payload), hash_func=hash_func, override_hash=valid_hash)

    return build_archive(payload, hash_func=hash_func, override_hash=override_hash)

def make_zip(entries: dict) -> bytes:
    """Create in-memory zip archive from dict of name -> bytes"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()

def generate_all_fixtures(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    print(f"Generating fixtures in: {output_dir}")

    # 1. Valid Minimal DAR (LF 2.1)
    dalf_bytes = create_dalf(minor="1", package_name="sample-contract", package_version="0.1.0", modules=["AssetHolding"])
    manifest = (
        "Manifest-Version: 1.0\r\n"
        "Created-By: damlc 3.7.0\r\n"
        "Main-Dalf: sample-contract.dalf\r\n"
        "Format: daml-lf\r\n"
        "Name: sample-contract\r\n"
        "Version: 0.1.0\r\n"
        "Sdk-Version: 3.7.1\r\n"
    )
    dar1 = make_zip({
        "META-INF/MANIFEST.MF": manifest.encode("utf-8"),
        "sample-contract.dalf": dalf_bytes,
    })
    with open(os.path.join(output_dir, "valid_minimal.dar"), "wb") as f:
        f.write(dar1)

    # 2. Valid Multi-DALF DAR (main + dependencies)
    main_dalf = create_dalf(minor="1", package_name="multidalf-contract", package_version="1.0.0", modules=["Main", "Helper"])
    prim_dalf = create_dalf(minor="1", package_name="daml-prim", package_version="0.1.0", modules=["GHC.Types"])
    stdlib_dalf = create_dalf(minor="1", package_name="daml-stdlib", package_version="0.1.0", modules=["DA.List", "DA.Optional"])
    manifest_multi = (
        "Manifest-Version: 1.0\r\n"
        "Created-By: damlc 3.7.0\r\n"
        "Main-Dalf: main.dalf\r\n"
        "Dalfs: daml-prim.dalf daml-stdlib.dalf\r\n"
        "Format: daml-lf\r\n"
        "Name: multidalf-contract\r\n"
        "Version: 1.0.0\r\n"
        "Sdk-Version: 3.7.1\r\n"
    )
    dar_multi = make_zip({
        "META-INF/MANIFEST.MF": manifest_multi.encode("utf-8"),
        "main.dalf": main_dalf,
        "daml-prim.dalf": prim_dalf,
        "daml-stdlib.dalf": stdlib_dalf,
    })
    with open(os.path.join(output_dir, "valid_multidalf.dar"), "wb") as f:
        f.write(dar_multi)

    # 3. Valid RFC 822 Folded Manifest (Line Wrapping with Spaces)
    manifest_folded = (
        "Manifest-Version: 1.0\r\n"
        "Created-By: damlc 3.7.0\r\n"
        "Main-Dalf: sample-very-long-name-contract-main-package-with-deep-hierarchy\r\n"
        " .dalf\r\n"
        "Dalfs: daml-prim.dalf\r\n"
        "  daml-stdlib.dalf\r\n"
        "Format: daml-lf\r\n"
        "Name: folded-contract\r\n"
        "Version: 0.1.0\r\n"
        "Sdk-Version: 3.7.1\r\n"
    )
    dar_folded = make_zip({
        "META-INF/MANIFEST.MF": manifest_folded.encode("utf-8"),
        "sample-very-long-name-contract-main-package-with-deep-hierarchy.dalf": dalf_bytes,
        "daml-prim.dalf": prim_dalf,
        "daml-stdlib.dalf": stdlib_dalf,
    })
    with open(os.path.join(output_dir, "valid_folded_manifest.dar"), "wb") as f:
        f.write(dar_folded)

    # 4. Valid LF Minors: 2.2, 2.3, 2.4
    for minor in ("2", "3", "4"):
        d = create_dalf(minor=minor, package_name=f"contract-lf2{minor}", package_version="0.1.0")
        m = (
            f"Manifest-Version: 1.0\r\n"
            f"Main-Dalf: contract.dalf\r\n"
            f"Format: daml-lf\r\n"
            f"Name: contract-lf2{minor}\r\n"
            f"Version: 0.1.0\r\n"
            f"Sdk-Version: 3.7.1\r\n"
        )
        with open(os.path.join(output_dir, f"valid_lf2{minor}.dar"), "wb") as f:
            f.write(make_zip({"META-INF/MANIFEST.MF": m.encode("utf-8"), "contract.dalf": d}))

    # 5. Corrupted: Not a zip archive (Bad Magic)
    with open(os.path.join(output_dir, "corrupt_bad_magic.dar"), "wb") as f:
        f.write(b"NOT_A_ZIP_ARCHIVE_DATA_PAYLOAD_TEST_CORRUPTION\n")

    # 6. Corrupted: Missing Manifest
    dar_no_manifest = make_zip({
        "sample-contract.dalf": dalf_bytes,
    })
    with open(os.path.join(output_dir, "corrupt_no_manifest.dar"), "wb") as f:
        f.write(dar_no_manifest)

    # 7. Corrupted: Manifest Missing Main-Dalf
    manifest_no_main = (
        "Manifest-Version: 1.0\r\n"
        "Name: no-main\r\n"
        "Format: daml-lf\r\n"
    )
    dar_no_main = make_zip({
        "META-INF/MANIFEST.MF": manifest_no_main.encode("utf-8"),
        "sample.dalf": dalf_bytes,
    })
    with open(os.path.join(output_dir, "corrupt_no_main_dalf.dar"), "wb") as f:
        f.write(dar_no_main)

    # 8. Corrupted: Main-Dalf in Manifest does not exist in ZIP
    manifest_missing_file = (
        "Manifest-Version: 1.0\r\n"
        "Main-Dalf: nonexistent_target_package.dalf\r\n"
        "Format: daml-lf\r\n"
    )
    dar_missing_file = make_zip({
        "META-INF/MANIFEST.MF": manifest_missing_file.encode("utf-8"),
        "different_file.dalf": dalf_bytes,
    })
    with open(os.path.join(output_dir, "corrupt_missing_main_file.dar"), "wb") as f:
        f.write(dar_missing_file)

    # 9. Corrupted: Invalid UTF-8 in MANIFEST.MF
    invalid_utf8_manifest = b"Manifest-Version: 1.0\r\nMain-Dalf: main.dalf\r\nName: \xff\xfe\x00corrupt\r\n"
    dar_bad_utf8 = make_zip({
        "META-INF/MANIFEST.MF": invalid_utf8_manifest,
        "main.dalf": dalf_bytes,
    })
    with open(os.path.join(output_dir, "corrupt_invalid_utf8.dar"), "wb") as f:
        f.write(dar_bad_utf8)

    # 10. Corrupted: Tampered Payload (AT-A04 Package ID mismatch)
    tampered_dalf = create_dalf(minor="1", tamper_payload=True)
    dar_tampered = make_zip({
        "META-INF/MANIFEST.MF": manifest.encode("utf-8"),
        "sample-contract.dalf": tampered_dalf,
    })
    with open(os.path.join(output_dir, "corrupt_tampered_payload.dar"), "wb") as f:
        f.write(dar_tampered)

    # 11. Corrupted: Unsupported Hash Function enum (e.g. 7)
    bad_hash_dalf = create_dalf(minor="1", hash_func=7)
    dar_bad_hash = make_zip({
        "META-INF/MANIFEST.MF": manifest.encode("utf-8"),
        "sample-contract.dalf": bad_hash_dalf,
    })
    with open(os.path.join(output_dir, "corrupt_bad_hash_func.dar"), "wb") as f:
        f.write(dar_bad_hash)

    # 12. Corrupted: Legacy LF 1.x (AT-A06 Major version rejection)
    lf1_dalf = create_dalf(minor="15", sum_type="lf1")
    dar_lf1 = make_zip({
        "META-INF/MANIFEST.MF": manifest.encode("utf-8"),
        "sample-contract.dalf": lf1_dalf,
    })
    with open(os.path.join(output_dir, "corrupt_legacy_lf1.dar"), "wb") as f:
        f.write(dar_lf1)

    # 13. Corrupted: Unsupported LF 2 Minor ("99") (AT-A06)
    unknown_minor_dalf = create_dalf(minor="99", sum_type="lf2")
    dar_unknown_minor = make_zip({
        "META-INF/MANIFEST.MF": manifest.encode("utf-8"),
        "sample-contract.dalf": unknown_minor_dalf,
    })
    with open(os.path.join(output_dir, "corrupt_unknown_minor.dar"), "wb") as f:
        f.write(dar_unknown_minor)

    # 14. Corrupted: Interned string index out of bounds (AT-A08)
    oob_dalf = create_dalf(minor="1", oob_name_idx=99999)
    dar_oob = make_zip({
        "META-INF/MANIFEST.MF": manifest.encode("utf-8"),
        "sample-contract.dalf": oob_dalf,
    })
    with open(os.path.join(output_dir, "corrupt_interned_oob.dar"), "wb") as f:
        f.write(dar_oob)

    # 15. Adversarial: Path Traversal Attack (AT-A02)
    # Using raw zip header to ensure zipfile doesn't sanitize the path
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest.encode("utf-8"))
        # Force entry with ../
        zinfo = zipfile.ZipInfo("../../etc/passwd_evil.dalf")
        zf.writestr(zinfo, dalf_bytes)
    with open(os.path.join(output_dir, "attack_path_traversal.dar"), "wb") as f:
        f.write(buf.getvalue())

    # 16. Adversarial: Single entry decompression bomb > 256 MiB (AT-A01)
    # 257 MiB of zeros compressed with ZIP_DEFLATED produces a tiny archive (< 300 KB)
    bomb_buf = io.BytesIO()
    with zipfile.ZipFile(bomb_buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest.encode("utf-8"))
        zinfo = zipfile.ZipInfo("sample-contract.dalf")
        zinfo.compress_type = zipfile.ZIP_DEFLATED
        zeros_chunk = b"\x00" * (1024 * 1024)
        with zf.open(zinfo, "w") as dest:
            for _ in range(257):
                dest.write(zeros_chunk)
    with open(os.path.join(output_dir, "attack_entry_bomb.dar"), "wb") as f:
        f.write(bomb_buf.getvalue())

    # 17. Adversarial: Cumulative archive decompression budget > 2 GiB (AT-A01)
    # 9 entries of 250 MiB zeros (total uncompressed = 2.25 GiB > 2.0 GiB cap)
    budget_buf = io.BytesIO()
    with zipfile.ZipFile(budget_buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest.encode("utf-8"))
        zeros_chunk = b"\x00" * (1024 * 1024)
        for i in range(9):
            zinfo = zipfile.ZipInfo(f"dep_{i}.dalf")
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            with zf.open(zinfo, "w") as dest:
                for _ in range(250):
                    dest.write(zeros_chunk)
    with open(os.path.join(output_dir, "attack_total_budget.dar"), "wb") as f:
        f.write(budget_buf.getvalue())

    print(f"Successfully generated all {17} fixtures in {output_dir}")

if __name__ == "__main__":
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "fixtures")
    generate_all_fixtures(os.path.abspath(out_dir))
