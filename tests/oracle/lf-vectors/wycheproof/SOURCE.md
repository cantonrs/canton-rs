# Project Wycheproof 테스트 벡터 (출처와 라이선스)

- **무엇**: ECDSA secp256k1 / SHA-256 서명 검증 벡터 476개(`ecdsa_secp256k1_sha256_test.json`, 스키마 `ecdsa_verify_schema_v1`, 원본 표기 `google-wycheproof 0.9rc5`).
- **출처**: https://github.com/C2SP/wycheproof, 커밋 `65ca494727a52944c204441c860b039e6786b99b`, 경로 `testvectors_v1/ecdsa_secp256k1_sha256_test.json`. 받은 날: 2026-11-12. 파일을 고치지 않았다.
- **SHA-256**: `ecdsa_secp256k1_sha256_test.json` = `43db761c0a2eae71fb0755d355d5130e28ce64a5b07846cf27e7072082597a81`, `LICENSE` = `58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd`.
- **라이선스**: Apache License 2.0(같은 디렉터리의 `LICENSE`, 저장소 `LICENSE-APACHE`와 바이트까지 같지는 않으나 같은 Apache-2.0 본문이다). 이 저장소도 Apache-2.0 단일 라이선스이므로 그대로 둘 수 있다([LICENSING.md](../../../../LICENSING.md)의 `tests/oracle/lf-vectors`).
- **쓰는 곳**: `scripts/gen-wycheproof-secp.py`가 Daml 값으로 바꾸고 `scripts/verify-wycheproof.sh`가 JVM과 Rust를 맞춘다([S-CRYPTO-006](../../../../doc/slices/S-CRYPTO-006.md)).
