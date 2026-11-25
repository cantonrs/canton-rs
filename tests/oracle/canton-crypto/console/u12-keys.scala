// U-12 console section 1: public and private key variants (accept/reject matrix).
// Appended to the bootstrap script by scripts/gen-canton-crypto.py. It relies on the preamble defined there:
// `pure` (CryptoPureApi), `hex`, `msg`, `usage`, `tc`.
//
// Output lines (tab separated, after the `ORA ` prefix):
//   pk  <label>/<case>  <input: v30.SigningPublicKey bytes>  <OK|ERR|THROW>  <class>  <detail>  <key id>
//   sk  <label>/<case>  <input: v30.SigningPrivateKey bytes> <OK|ERR|THROW>  <class>  <detail>  <derived public key SPKI>  <sign result>
//   pkcache <label> <other spec> <first> <second, cache kept> <second, cache cleared>
// Every case clears the node's key-validation caches first (`CryptoKeyValidation.clearValidationCaches`): the caches are keyed by
// the key fingerprint, which does not cover the key spec, so a result could otherwise depend on the order of the cases.
import org.bouncycastle.asn1.{ASN1Encodable, ASN1Integer, ASN1ObjectIdentifier, DERNull, DEROctetString, DERSequence}
import org.bouncycastle.asn1.x509.{AlgorithmIdentifier, SubjectPublicKeyInfo}
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x9.{ECNamedCurveTable, X9ObjectIdentifiers}
import org.bouncycastle.asn1.sec.{SECObjectIdentifiers, ECPrivateKey => BcEcPrivateKey}
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import com.digitalasset.canton.crypto.{v30 => cv30}
// (no `import scala.util...`: it makes the console compiler load Scala 3 TASTy files and fail; names are fully qualified)
import java.math.BigInteger

def u_bs(a: Array[Byte]): ByteString = ByteString.copyFrom(a)
def u_norm(s: String): String = s.replaceAll("1220[0-9a-f]{64}", "<fp>").replaceAll("[\\t\\r\\n]+", " ").take(240)
def u_cls(o: Any): String = o.getClass.getSimpleName
def u_res[A, B](r: scala.util.Try[Either[A, B]])(ok: B => String): (String, String, String) = r match {
  case scala.util.Success(Right(v)) => ("OK", "-", ok(v))
  case scala.util.Success(Left(e)) => ("ERR", u_cls(e), u_norm(e.toString))
  case scala.util.Failure(t) => ("THROW", u_cls(t), u_norm(String.valueOf(t.getMessage)))
}
def setAt(a: Array[Byte], i: Int, v: Int): Array[Byte] = { val c = a.clone(); c(i) = v.toByte; c }
def u_mut(a: Array[Byte], i: Int): Array[Byte] = { val c = a.clone(); c(i) = (c(i) ^ 0x01).toByte; c }
def u_fix(v: BigInteger, len: Int): Array[Byte] = {
  val b = v.toByteArray.dropWhile(_ == 0)
  Array.fill[Byte](math.max(0, len - b.length))(0) ++ b
}
// rewrite the DER length of the outer SEQUENCE in the (non-minimal) 4-byte long form
def u_relen(a: Array[Byte]): Array[Byte] = {
  val (hdr, len) =
    if ((a(1) & 0x80) == 0) (2, a(1) & 0xff)
    else { val n = a(1) & 0x7f; (2 + n, a.slice(2, 2 + n).foldLeft(0)((acc, b) => (acc << 8) | (b & 0xff))) }
  Array[Byte](a(0), 0x84.toByte, ((len >> 24) & 0xff).toByte, ((len >> 16) & 0xff).toByte, ((len >> 8) & 0xff).toByte, (len & 0xff).toByte) ++ a.drop(hdr)
}
val u_curveOids = Map("EcP256" -> SECObjectIdentifiers.secp256r1, "EcP384" -> SECObjectIdentifiers.secp384r1, "EcSecp256k1" -> SECObjectIdentifiers.secp256k1)
val u_curveNames = Map("EcP256" -> "secp256r1", "EcP384" -> "secp384r1", "EcSecp256k1" -> "secp256k1")
def u_order(label: String): BigInteger = ECNamedCurveTable.getByName(u_curveNames(label)).getN
val u_hash = pure.digest(HashPurpose.SequencedEventSignature, msg)

def u_pkTrial(label: String, n: String, m: cv30.SigningPublicKey): Unit = {
  CryptoKeyValidation.clearValidationCaches()
  val r = scala.util.Try(SigningPublicKey.fromProtoV30(m))
  val (ok, cls, detail) = u_res(r)(k => k.keySpec + "|" + k.format + "|" + k.usage.toList.map(_.toString).sorted.mkString(","))
  val id = r.toOption.flatMap(_.toOption).map(_.id.unwrap).getOrElse("-")
  println(List("ORA pk", label + "/" + n, hex(m.toByteString), ok, cls, detail, id).mkString("\t"))
}

def u_pkCases(label: String, specNum: Int, pm: cv30.SigningPublicKey): Seq[(String, cv30.SigningPublicKey)] = {
  val spkiB = pm.publicKey.toByteArray
  val info = SubjectPublicKeyInfo.getInstance(spkiB)
  val rawPt = info.getPublicKeyData.getBytes
  def w(b: Array[Byte]): cv30.SigningPublicKey = pm.copy(publicKey = u_bs(b))
  def fmt(n: Int) = cv30.CryptoKeyFormat.fromValue(n)
  def spec(n: Int) = cv30.SigningKeySpec.fromValue(n)
  def scheme(n: Int) = cv30.SigningKeyScheme.fromValue(n)
  def use(ns: Int*) = ns.map(cv30.SigningKeyUsage.fromValue(_))
  val ec = label != "Ed25519"
  val common = Seq[(String, cv30.SigningPublicKey)](
    ("valid", pm),
    ("formatDer2", pm.copy(format = fmt(2))), ("formatRaw3", pm.copy(format = fmt(3))), ("formatPkcs8", pm.copy(format = fmt(5))),
    ("formatSymbolic", pm.copy(format = fmt(10000))), ("formatUnspecified", pm.copy(format = fmt(0))), ("formatUnknown99", pm.copy(format = fmt(99))),
    ("derFormatRawPoint", pm.copy(format = fmt(2), publicKey = u_bs(rawPt))),
    ("rawFormatRawPoint", pm.copy(format = fmt(3), publicKey = u_bs(rawPt))),
    ("spkiFormatRawPoint", w(rawPt)),
    ("specUnspecified", pm.copy(keySpec = spec(0))),
    ("schemeEd25519Only", pm.copy(keySpec = spec(0), scheme = scheme(1))),
    ("schemeP256Only", pm.copy(keySpec = spec(0), scheme = scheme(2))),
    ("schemeP384Only", pm.copy(keySpec = spec(0), scheme = scheme(3))),
    ("schemeUnknown99Only", pm.copy(keySpec = spec(0), scheme = scheme(99))),
    ("schemeP384WithSpec", pm.copy(scheme = scheme(3))), ("schemeUnknown99WithSpec", pm.copy(scheme = scheme(99))),
    ("derFormatSchemeOnly", pm.copy(format = fmt(2), keySpec = spec(0), scheme = scheme(specNum.min(3)))),
    ("usageNone", pm.copy(usage = Seq.empty[cv30.SigningKeyUsage])), ("usageNamespace", pm.copy(usage = use(1))),
    ("usageIdentityDelegation", pm.copy(usage = use(2))), ("usageSequencerAuth", pm.copy(usage = use(3))),
    ("usageProofOfOwnership", pm.copy(usage = use(5))), ("usageNamespaceProtocol", pm.copy(usage = use(1, 4))),
    ("usageUnspecified", pm.copy(usage = use(0))), ("usageUnknown99", pm.copy(usage = use(99))),
    ("empty", w(Array.empty[Byte])), ("trailingByte", w(spkiB :+ 0.toByte)), ("truncated", w(spkiB.dropRight(1))),
    ("dropFirst", w(spkiB.drop(1))), ("relen4", w(u_relen(spkiB))),
    ("indefiniteLength", w(Array[Byte](0x30, 0x80.toByte) ++ spkiB.drop(2) ++ Array[Byte](0, 0))),
    ("outerSet", w(0x31.toByte +: spkiB.drop(1))),
    ("bitStringUnused8", w(setAt(spkiB, spkiB.length - rawPt.length - 1, 8))),
    ("extraTrailingElement", w(new DERSequence(Array[ASN1Encodable](info.getAlgorithm, info.getPublicKeyData, DERNull.INSTANCE)).getEncoded)),
    ("symbolicGarbage", pm.copy(format = fmt(10000), publicKey = u_bs(Array[Byte](1, 2, 3)))),
    ("symbolicEmpty", pm.copy(format = fmt(10000), publicKey = ByteString.EMPTY)),
  ) ++ (1 to 5).filter(_ != specNum).map(n => ("spec" + n, pm.copy(keySpec = spec(n)))) ++ Seq(("spec99", pm.copy(keySpec = spec(99))))
  val specific: Seq[(String, cv30.SigningPublicKey)] = if (ec) {
    val n = (rawPt.length - 1) / 2
    val x = rawPt.slice(1, 1 + n)
    val y = rawPt.drop(1 + n)
    val oid = u_curveOids(label)
    def spkiOf(o: ASN1ObjectIdentifier, pt: Array[Byte]) = w(new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, o), pt).getEncoded)
    def spkiAlg(alg: AlgorithmIdentifier, pt: Array[Byte]) = w(new SubjectPublicKeyInfo(alg, pt).getEncoded)
    val ff = Array.fill[Byte](n)(0xff.toByte)
    val g = ECNamedCurveTable.getByName(u_curveNames(label)).getG.getEncoded(false)
    val spkiG = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, oid), g).getEncoded
    Seq(
      ("flipLast", w(u_mut(spkiB, spkiB.length - 1))),
      ("generator", w(spkiG)), ("generatorUnused1", w(setAt(spkiG, spkiG.length - g.length - 1, 1))),
      ("compressed", spkiOf(oid, Array((0x02 | (y.last & 1)).toByte) ++ x)),
      ("compressedWrongParity", spkiOf(oid, Array((0x03 - (y.last & 1)).toByte) ++ x)),
      ("hybrid", spkiOf(oid, Array((0x06 | (y.last & 1)).toByte) ++ x ++ y)),
      ("hybridWrongParity", spkiOf(oid, Array((0x07 - (y.last & 1)).toByte) ++ x ++ y)),
      ("infinity", spkiOf(oid, Array(0.toByte))),
      ("zeroPoint", spkiOf(oid, Array(0x04.toByte) ++ Array.fill[Byte](2 * n)(0))),
      ("xAboveField", spkiOf(oid, Array(0x04.toByte) ++ ff ++ y)),
      ("yAboveField", spkiOf(oid, Array(0x04.toByte) ++ x ++ ff)),
      ("yLastByteFlip", spkiOf(oid, u_mut(rawPt, rawPt.length - 1))),
      ("xLastByteFlip", spkiOf(oid, u_mut(rawPt, n))),
      ("prefix05", spkiOf(oid, Array(0x05.toByte) ++ x ++ y)), ("prefix00Full", spkiOf(oid, Array(0x00.toByte) ++ x ++ y)),
      ("shortPoint", spkiOf(oid, rawPt.dropRight(1))), ("longPoint", spkiOf(oid, rawPt :+ 0.toByte)),
      ("paramsAbsent", spkiAlg(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey), rawPt)),
      ("paramsNull", spkiAlg(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, DERNull.INSTANCE), rawPt)),
      ("algEd25519Oid", spkiAlg(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), rawPt)),
      ("algX25519Oid", spkiAlg(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), rawPt)),
    ) ++ u_curveOids.toSeq.map { case (l, o) => ("curveOid" + l, spkiOf(o, rawPt)) }
  } else {
    def ed(pt: Array[Byte]) = w(new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), pt).getEncoded)
    def le(first: Int, last: Int) = { val a = Array.fill[Byte](32)(0); a(0) = first.toByte; a(31) = last.toByte; a }
    val ffs = Array.fill[Byte](32)(0xff.toByte)
    val nonCanon = ffs.clone(); nonCanon(0) = 0xee.toByte; nonCanon(31) = 0x7f.toByte
    val order2 = ffs.clone(); order2(0) = 0xec.toByte; order2(31) = 0x7f.toByte
    val signFlip = rawPt.clone(); signFlip(31) = (signFlip(31) ^ 0x80).toByte
    val basePt = "5866666666666666666666666666666666666666666666666666666666666666".grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
    val spkiB25519 = new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), basePt).getEncoded
    Seq(
      ("generator", w(spkiB25519)), ("generatorUnused1", w(setAt(spkiB25519, spkiB25519.length - 33, 1))),
      ("identity", ed(le(1, 0))), ("order2", ed(order2)), ("order4Y0", ed(le(0, 0))), ("nonCanonicalIdentity", ed(nonCanon)),
      ("identityWithSignBit", ed(le(1, 0x80))), ("y2", ed(le(2, 0))), ("y3", ed(le(3, 0))), ("allFF", ed(ffs)),
      ("signFlip", ed(signFlip)), ("pt31", ed(rawPt.dropRight(1))), ("pt33", ed(rawPt :+ 0.toByte)),
      ("paramsNull", w(new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519, DERNull.INSTANCE), rawPt).getEncoded)),
      ("algX25519Oid", w(new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), rawPt).getEncoded)),
      ("algEcP256Oid", w(new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, SECObjectIdentifiers.secp256r1), rawPt).getEncoded)),
    )
  }
  common ++ specific
}

val u_specs = List(("Ed25519", SigningKeySpec.EcCurve25519, 1), ("EcP256", SigningKeySpec.EcP256, 2), ("EcP384", SigningKeySpec.EcP384, 3), ("EcSecp256k1", SigningKeySpec.EcSecp256k1, 4))

// ---- public keys ----
u_specs.foreach { case (label, spec, specNum) =>
  val pk0 = p1.keys.secret.generate_signing_key("u12-pk-" + label, usage, Some(spec))
  val pm = pk0.toProtoV30.toOption.get
  u_pkCases(label, specNum, pm).foreach { case (n, m) => u_pkTrial(label, n, m) }
  // the validation cache is keyed by the fingerprint, which does not include the key spec: measure the effect of the order
  val other = if (specNum == 2) 3 else 2
  def first(m: cv30.SigningPublicKey): String = scala.util.Try(SigningPublicKey.fromProtoV30(m)).map(_.fold(e => "ERR:" + u_cls(e), _ => "OK")).getOrElse("THROW")
  CryptoKeyValidation.clearValidationCaches()
  val a = first(pm)
  val b = first(pm.copy(keySpec = cv30.SigningKeySpec.fromValue(other)))
  CryptoKeyValidation.clearValidationCaches()
  val c = first(pm.copy(keySpec = cv30.SigningKeySpec.fromValue(other)))
  println(List("ORA pkcache", label, other.toString, a, b, c).mkString("\t"))
}

// ---- private keys ----
def u_skTrial(label: String, n: String, m: cv30.SigningPrivateKey): Unit = {
  CryptoKeyValidation.clearValidationCaches()
  val r = scala.util.Try(SigningPrivateKey.fromProtoV30(m))
  val (ok, cls, detail) = u_res(r)(k => k.keySpec + "|" + k.format + "|" + k.usage.toList.map(_.toString).sorted.mkString(","))
  val (pub, sg) = r match {
    case scala.util.Success(Right(k)) =>
      val p = scala.util.Try(SigningKeyPair.create(k)).toOption.flatMap(_.toOption).flatMap(kp => kp.publicKey.toProtoV30.toOption).map(p => hex(p.publicKey)).getOrElse("-")
      val s = scala.util.Try(pure.sign(u_hash, k, usage)) match { case scala.util.Success(Right(_)) => "OK"; case scala.util.Success(Left(e)) => u_cls(e); case scala.util.Failure(t) => "THROW" }
      (p, s)
    case _ => ("-", "-")
  }
  println(List("ORA sk", label + "/" + n, hex(m.toByteString), ok, cls, detail, pub, sg).mkString("\t"))
}

def u_skCases(label: String, specNum: Int, sm: cv30.SigningPrivateKey): Seq[(String, cv30.SigningPrivateKey)] = {
  val pk8 = sm.privateKey.toByteArray
  def w(b: Array[Byte]): cv30.SigningPrivateKey = sm.copy(privateKey = u_bs(b))
  def fmt(n: Int) = cv30.CryptoKeyFormat.fromValue(n)
  def spec(n: Int) = cv30.SigningKeySpec.fromValue(n)
  def scheme(n: Int) = cv30.SigningKeyScheme.fromValue(n)
  def use(ns: Int*) = ns.map(cv30.SigningKeyUsage.fromValue(_))
  val common = Seq[(String, cv30.SigningPrivateKey)](
    ("valid", sm),
    ("formatDer2", sm.copy(format = fmt(2))), ("formatRaw3", sm.copy(format = fmt(3))), ("formatSpki4", sm.copy(format = fmt(4))),
    ("formatSymbolic", sm.copy(format = fmt(10000))), ("formatUnspecified", sm.copy(format = fmt(0))), ("formatUnknown99", sm.copy(format = fmt(99))),
    ("specUnspecified", sm.copy(keySpec = spec(0))),
    ("schemeEd25519Only", sm.copy(keySpec = spec(0), scheme = scheme(1))),
    ("schemeP256Only", sm.copy(keySpec = spec(0), scheme = scheme(2))),
    ("schemeP384Only", sm.copy(keySpec = spec(0), scheme = scheme(3))),
    ("schemeUnknown99Only", sm.copy(keySpec = spec(0), scheme = scheme(99))),
    ("schemeP384WithSpec", sm.copy(scheme = scheme(3))),
    ("idEmpty", sm.copy(id = "")), ("idNotFingerprint", sm.copy(id = "not a fingerprint")), ("idShortHex", sm.copy(id = "1220ab")),
    ("idLong80", sm.copy(id = "a" * 80)), ("idLong300", sm.copy(id = "a" * 300)), ("idInvalidChars", sm.copy(id = "bad!id")), ("idUnicode", sm.copy(id = "\u00e9")), ("idUpperHex", sm.copy(id = "1220" + "A" * 64)),
    ("usageNone", sm.copy(usage = Seq.empty[cv30.SigningKeyUsage])), ("usageNamespace", sm.copy(usage = use(1))),
    ("usageUnknown99", sm.copy(usage = use(99))),
    ("empty", w(Array.empty[Byte])), ("trailingByte", w(pk8 :+ 0.toByte)), ("truncated", w(pk8.dropRight(1))),
    ("dropFirst", w(pk8.drop(1))), ("relen4", w(u_relen(pk8))), ("flipLast", w(u_mut(pk8, pk8.length - 1))),
    ("indefiniteLength", w(Array[Byte](0x30, 0x80.toByte) ++ pk8.drop(if ((pk8(1) & 0x80) == 0) 2 else 2 + (pk8(1) & 0x7f)) ++ Array[Byte](0, 0))),
    ("outerSet", w(0x31.toByte +: pk8.drop(1))),
    ("outerVersion1", w(setAt(pk8, (if ((pk8(1) & 0x80) == 0) 2 else 2 + (pk8(1) & 0x7f)) + 2, 1))),
    ("outerVersion2", w(setAt(pk8, (if ((pk8(1) & 0x80) == 0) 2 else 2 + (pk8(1) & 0x7f)) + 2, 2))),
    ("symbolicGarbage", sm.copy(format = fmt(10000), privateKey = u_bs(Array[Byte](1, 2, 3)))),
    ("symbolicEmpty", sm.copy(format = fmt(10000), privateKey = ByteString.EMPTY)),
  ) ++ (1 to 5).filter(_ != specNum).map(n => ("spec" + n, sm.copy(keySpec = spec(n)))) ++ Seq(("spec99", sm.copy(keySpec = spec(99))))
  val specific: Seq[(String, cv30.SigningPrivateKey)] = if (label != "Ed25519") {
    val order = u_order(label)
    val bits = order.bitLength
    val len = (bits + 7) / 8
    val oid = u_curveOids(label)
    def pkcs8(alg: AlgorithmIdentifier, d: BigInteger) = w(new PrivateKeyInfo(alg, new BcEcPrivateKey(bits, d)).getEncoded)
    val myAlg = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, oid)
    Seq(
      ("dZero", pkcs8(myAlg, BigInteger.ZERO)), ("dOne", pkcs8(myAlg, BigInteger.ONE)), ("dTwo", pkcs8(myAlg, BigInteger.valueOf(2))),
      ("dNMinus1", pkcs8(myAlg, order.subtract(BigInteger.ONE))), ("dN", pkcs8(myAlg, order)), ("dNPlus1", pkcs8(myAlg, order.add(BigInteger.ONE))),
      ("dAllOnes", pkcs8(myAlg, BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE))),
      ("dLen33", w(new PrivateKeyInfo(myAlg, new DERSequence(Array[ASN1Encodable](new ASN1Integer(1), new DEROctetString(Array[Byte](0) ++ u_fix(BigInteger.TWO, len))))).getEncoded)),
      ("dLen1", w(new PrivateKeyInfo(myAlg, new DERSequence(Array[ASN1Encodable](new ASN1Integer(1), new DEROctetString(Array[Byte](2))))).getEncoded)),
      ("dLen0", w(new PrivateKeyInfo(myAlg, new DERSequence(Array[ASN1Encodable](new ASN1Integer(1), new DEROctetString(Array.empty[Byte])))).getEncoded)),
      ("versionTwo", w(new PrivateKeyInfo(myAlg, new DERSequence(Array[ASN1Encodable](new ASN1Integer(2), new DEROctetString(u_fix(BigInteger.TWO, len))))).getEncoded)),
      ("innerNoVersion", w(new PrivateKeyInfo(myAlg, new DERSequence(Array[ASN1Encodable](new DEROctetString(u_fix(BigInteger.TWO, len))))).getEncoded)),
      ("innerIsInteger", w(new PrivateKeyInfo(myAlg, new ASN1Integer(2)).getEncoded)),
      ("paramsAbsent", pkcs8(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey), BigInteger.TWO)),
      ("paramsNull", pkcs8(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, DERNull.INSTANCE), BigInteger.TWO)),
      ("algEd25519Oid", w(new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), new DEROctetString(Array.fill[Byte](32)(7))).getEncoded)),
    ) ++ u_curveOids.toSeq.map { case (l, o) => ("curveOid" + l + "D2", pkcs8(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, o), BigInteger.TWO)) }
  } else {
    def ed(alg: AlgorithmIdentifier, seed: Array[Byte]) = w(new PrivateKeyInfo(alg, new DEROctetString(seed)).getEncoded)
    val edAlg = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
    Seq(
      ("rawSeedRawFormat", sm.copy(format = fmt(3), privateKey = u_bs(pk8.takeRight(32)))),
      ("rawSeed31RawFormat", sm.copy(format = fmt(3), privateKey = u_bs(pk8.takeRight(31)))),
      ("rawSeed33RawFormat", sm.copy(format = fmt(3), privateKey = u_bs(Array[Byte](0) ++ pk8.takeRight(32)))),
      ("seedZeros", ed(edAlg, Array.fill[Byte](32)(0))), ("seedAllFF", ed(edAlg, Array.fill[Byte](32)(0xff.toByte))),
      ("seed31", ed(edAlg, Array.fill[Byte](31)(7))), ("seed33", ed(edAlg, Array.fill[Byte](33)(7))), ("seed0", ed(edAlg, Array.empty[Byte])),
      ("paramsNull", ed(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519, DERNull.INSTANCE), Array.fill[Byte](32)(7))),
      ("algX25519Oid", ed(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), Array.fill[Byte](32)(7))),
      ("algEcP256Oid", ed(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, SECObjectIdentifiers.secp256r1), Array.fill[Byte](32)(7))),
    )
  }
  common ++ specific
}

u_specs.foreach { case (label, spec, specNum) =>
  val pk0 = p1.keys.secret.generate_signing_key("u12-sk-" + label, usage, Some(spec))
  val kp0 = CryptoKeyPair.fromTrustedByteString(p1.keys.secret.download(pk0.fingerprint)).toOption.get.asInstanceOf[SigningKeyPair]
  val sm = kp0.privateKey.toProtoV30.toOption.get
  u_skCases(label, specNum, sm).foreach { case (n, m) => u_skTrial(label, n, m) }
}
