// U-13 part (i) console section: the wire form of the `Signature` message (reordered, duplicated and unknown fields, wrong
// wire types, bad varints, the version wrapper, a session-key delegation). Appended after u12-signatures.scala, whose helpers
// (`u_bs`, `u_res`, `u_sgKeys`, `u_hash`, ...) it uses.
//
//   sgp  <label>/<case>  <p = raw v30.Signature bytes | w = version-wrapped bytes>  <input>  <OK|ERR|THROW>  <class>  <detail>
//        for OK the detail is the parsed message read back as `format|algorithm spec|signed_by|signature|delegation`.
// ---- wire form of the message (U-13 part i): what `v30.Signature.parseFrom` and `fromProtoV30` make of hand-built bytes ----
def u_vi(n: Long): Array[Byte] = {
  var v = n; val o = new java.io.ByteArrayOutputStream()
  while ((v & ~0x7fL) != 0) { o.write(((v & 0x7f) | 0x80).toInt); v = v >>> 7 }
  o.write(v.toInt); o.toByteArray
}
def u_tag(num: Int, wt: Int): Array[Byte] = u_vi((num.toLong << 3) | wt)
def u_varf(num: Int, v: Long): Array[Byte] = u_tag(num, 0) ++ u_vi(v)
def u_lenf(num: Int, b: Array[Byte]): Array[Byte] = u_tag(num, 2) ++ u_vi(b.length.toLong) ++ b
def u_wrap(d: Array[Byte], ver: Long): Array[Byte] = u_lenf(1, d) ++ u_varf(2, ver)

def u_sgpTrial(label: String, n: String, b: Array[Byte], wrapped: Boolean): Unit = {
  CryptoKeyValidation.clearValidationCaches()
  val r = scala.util.Try(if (wrapped) Signature.fromTrustedByteString(u_bs(b)) else Signature.fromProtoV30(cv30.Signature.parseFrom(b)))
  val (ok, cls, detail) = u_res(r) { s =>
    val p = s.toProtoV30
    val d = p.signatureDelegation.map(d => hex(d.sessionKey) + "/" + d.sessionKeySpec.value + "/" + d.validityPeriodFromInclusive + "/" + d.validityPeriodDurationSeconds + "/" + d.format.value + "/" + hex(d.signature) + "/" + d.signingAlgorithmSpec.value).getOrElse("-")
    p.format.value + "|" + p.signingAlgorithmSpec.value + "|" + p.signedBy + "|" + hex(p.signature) + "|" + d
  }
  println(List("ORA sgp", label + "/" + n, if (wrapped) "w" else "p", hex(u_bs(b)), ok, cls, detail).mkString("\t"))
}

val u_session = p1.keys.secret.generate_signing_key("u12-session", usage, Some(SigningKeySpec.EcP256))
val u_sessionSpki = u_session.toProtoV30.toOption.get.publicKey

List("Ed25519", "EcP256").foreach { label =>
  val (_, pk, kp) = u_sgKeys.find(_._1 == label).get
  val sp = pure.sign(u_hash, kp.privateKey, usage).toOption.get.toProtoV30
  val fp = pk.fingerprint.unwrap.getBytes("UTF-8")
  val sigb = sp.signature.toByteArray
  val fm = sp.format.value
  val sv = sp.signingAlgorithmSpec.value
  val f1 = u_varf(1, fm.toLong); val f2 = u_lenf(2, sigb); val f3 = u_lenf(3, fp); val f4 = u_varf(4, sv.toLong)
  val canonical = f1 ++ f2 ++ f3 ++ f4
  def p(n: String, b: Array[Byte]) = u_sgpTrial(label, n, b, false)
  def w(n: String, b: Array[Byte]) = u_sgpTrial(label, n, b, true)
  p("canonical", canonical)
  p("reversed", f4 ++ f3 ++ f2 ++ f1); p("interleaved", f3 ++ f1 ++ f4 ++ f2); p("signatureFirst", f2 ++ f1 ++ f3 ++ f4)
  p("dupFormatFirstWins", u_varf(1, 1) ++ canonical)        // last occurrence wins
  p("dupFormatLastWins", canonical ++ u_varf(1, 1))
  p("dupSignatureLastWins", u_lenf(2, Array[Byte](1, 2, 3)) ++ canonical)
  p("dupSignedByLastWins", f3.take(0) ++ u_lenf(3, "junk".getBytes) ++ canonical)
  p("dupSpecLastWins", canonical ++ u_varf(4, 99))
  p("unknownVarint", canonical ++ u_varf(99, 5)); p("unknownLength", canonical ++ u_lenf(98, "x".getBytes))
  p("unknownFixed32", canonical ++ u_tag(97, 5) ++ Array[Byte](1, 2, 3, 4)); p("unknownFixed64", canonical ++ u_tag(96, 1) ++ Array.fill[Byte](8)(1))
  p("unknownGroup", canonical ++ u_tag(95, 3) ++ u_varf(1, 1) ++ u_tag(95, 4))
  p("unknownGroupUnterminated", canonical ++ u_tag(95, 3) ++ u_varf(1, 1))
  p("unknownBeforeKnown", u_varf(99, 5) ++ canonical)
  p("unknownField6", canonical ++ u_varf(6, 1))
  p("unknownLargeFieldNumber", canonical ++ u_varf(536870911, 1))
  p("formatAsLengthDelimited", u_lenf(1, Array[Byte](fm.toByte)) ++ f2 ++ f3 ++ f4)
  p("signatureAsVarint", f1 ++ u_varf(2, 5) ++ f3 ++ f4)
  p("signedByAsVarint", f1 ++ f2 ++ u_varf(3, 5) ++ f4)
  p("signedByAsFixed32", f1 ++ f2 ++ u_tag(3, 5) ++ Array[Byte](1, 2, 3, 4) ++ f4)
  p("specAsLengthDelimited", f1 ++ f2 ++ f3 ++ u_lenf(4, Array[Byte](sv.toByte)))
  p("delegationAsVarint", canonical ++ u_varf(5, 1))
  p("formatNonCanonicalVarint", u_tag(1, 0) ++ Array[Byte]((0x80 | fm).toByte, 0x00) ++ f2 ++ f3 ++ f4)
  p("formatVarintTooBig", u_varf(1, (1L << 32) + fm.toLong) ++ f2 ++ f3 ++ f4)
  p("formatNegative", u_varf(1, -1L) ++ f2 ++ f3 ++ f4)
  p("formatVarint11Bytes", u_tag(1, 0) ++ Array.fill[Byte](10)(0x80.toByte) ++ Array[Byte](1) ++ f2 ++ f3 ++ f4)
  p("signedByInvalidUtf8", f1 ++ f2 ++ u_lenf(3, Array[Byte](0xff.toByte, 0xfe.toByte)) ++ f4)
  p("signedByNul", f1 ++ f2 ++ u_lenf(3, Array[Byte](0x61, 0)) ++ f4)
  p("empty", Array.empty[Byte]); p("truncatedMiddle", canonical.dropRight(3)); p("truncatedAfterTag", canonical.take(1) ++ Array.empty[Byte])
  p("lengthOverrun", f1 ++ u_tag(2, 2) ++ u_vi(1000) ++ Array[Byte](1, 2, 3))
  p("tagZero", Array[Byte](0, 0) ++ canonical); p("wireType6", canonical ++ u_tag(50, 6)); p("wireType7", canonical ++ u_tag(50, 7))
  p("endGroupAlone", canonical ++ u_tag(95, 4))
  p("noFormat", f2 ++ f3 ++ f4); p("noSignature", f1 ++ f3 ++ f4); p("noSignedBy", f1 ++ f2 ++ f4); p("noSpec", f1 ++ f2 ++ f3)
  p("onlyFormat", f1)
  w("wrappedValid", u_wrap(canonical, 30)); w("wrappedV29", u_wrap(canonical, 29)); w("wrappedV31", u_wrap(canonical, 31))
  w("wrappedFieldsReversed", u_varf(2, 30) ++ u_lenf(1, canonical)); w("wrappedNoVersion", u_lenf(1, canonical))
  w("wrappedUnknownField", u_wrap(canonical, 30) ++ u_varf(15, 7)); w("wrappedBigVarint", u_wrap(canonical, (1L << 40) + 30))
  w("wrappedInnerUnknownField", u_wrap(canonical ++ u_varf(99, 5), 30)); w("wrappedEmpty", Array.empty[Byte])
}

// ---- the optional `signature_delegation` (field 5): a session key authorised by a long-term key ----
{
  val (_, pk, kp) = u_sgKeys.find(_._1 == "Ed25519").get
  val sp = pure.sign(u_hash, kp.privateKey, usage).toOption.get.toProtoV30
  val fp = pk.fingerprint.unwrap.getBytes("UTF-8")
  val base = u_varf(1, sp.format.value.toLong) ++ u_lenf(2, sp.signature.toByteArray) ++ u_lenf(3, fp) ++ u_varf(4, sp.signingAlgorithmSpec.value.toLong)
  val dg = cv30.SignatureDelegation.defaultInstance.copy(
    sessionKey = u_sessionSpki, sessionKeySpec = cv30.SigningKeySpec.fromValue(2), validityPeriodFromInclusive = 1700000000000000L,
    validityPeriodDurationSeconds = 3600, format = cv30.SignatureFormat.fromValue(2), signature = u_bs(Array[Byte](1, 2, 3, 4)),
    signingAlgorithmSpec = cv30.SigningAlgorithmSpec.fromValue(2))
  def d(n: String, m: cv30.SignatureDelegation) = u_sgpTrial("Ed25519", "delegation-" + n, base ++ u_lenf(5, m.toByteArray), false)
  u_sgpTrial("Ed25519", "delegation-emptyMessage", base ++ u_tag(5, 2) ++ Array[Byte](0), false)
  d("valid", dg)
  d("specUnspecified", dg.copy(sessionKeySpec = cv30.SigningKeySpec.fromValue(0))); d("specUnknown99", dg.copy(sessionKeySpec = cv30.SigningKeySpec.fromValue(99)))
  d("specEd25519ForP256Key", dg.copy(sessionKeySpec = cv30.SigningKeySpec.fromValue(1))); d("specP384ForP256Key", dg.copy(sessionKeySpec = cv30.SigningKeySpec.fromValue(3)))
  d("sessionKeyEmpty", dg.copy(sessionKey = ByteString.EMPTY)); d("sessionKeyGarbage", dg.copy(sessionKey = u_bs(Array[Byte](1, 2, 3))))
  d("sessionKeyTrailing", dg.copy(sessionKey = u_bs(u_sessionSpki.toByteArray :+ 0.toByte)))
  List(("zero", 0L), ("minusOne", -1L), ("min", -62135596800000000L), ("belowMin", -62135596800000001L), ("max", 253402300799999999L),
    ("aboveMax", 253402300800000000L), ("longMin", Long.MinValue), ("longMax", Long.MaxValue)).foreach { case (n, v) =>
    d("from-" + n, dg.copy(validityPeriodFromInclusive = v))
  }
  List(("zero", 0), ("one", 1), ("max", Int.MaxValue), ("minusOne", -1), ("intMin", Int.MinValue)).foreach { case (n, v) =>
    d("duration-" + n, dg.copy(validityPeriodDurationSeconds = v))
  }
  d("formatUnspecified", dg.copy(format = cv30.SignatureFormat.fromValue(0))); d("formatRaw", dg.copy(format = cv30.SignatureFormat.fromValue(1)))
  d("formatConcat", dg.copy(format = cv30.SignatureFormat.fromValue(3))); d("formatUnknown99", dg.copy(format = cv30.SignatureFormat.fromValue(99)))
  d("algoUnspecified", dg.copy(signingAlgorithmSpec = cv30.SigningAlgorithmSpec.fromValue(0))); d("algoUnknown99", dg.copy(signingAlgorithmSpec = cv30.SigningAlgorithmSpec.fromValue(99)))
  d("signatureEmpty", dg.copy(signature = ByteString.EMPTY))
  // two occurrences of the embedded message are merged field by field
  val part1 = cv30.SignatureDelegation.defaultInstance.copy(sessionKey = u_sessionSpki, sessionKeySpec = cv30.SigningKeySpec.fromValue(2), validityPeriodFromInclusive = 1700000000000000L)
  val part2 = cv30.SignatureDelegation.defaultInstance.copy(validityPeriodDurationSeconds = 60, format = cv30.SignatureFormat.fromValue(2), signature = u_bs(Array[Byte](9)), signingAlgorithmSpec = cv30.SigningAlgorithmSpec.fromValue(2))
  u_sgpTrial("Ed25519", "delegation-splitInTwo", base ++ u_lenf(5, part1.toByteArray) ++ u_lenf(5, part2.toByteArray), false)
  u_sgpTrial("Ed25519", "delegation-splitSecondOverrides", base ++ u_lenf(5, dg.toByteArray) ++ u_lenf(5, cv30.SignatureDelegation.defaultInstance.copy(validityPeriodDurationSeconds = 1).toByteArray), false)
}
