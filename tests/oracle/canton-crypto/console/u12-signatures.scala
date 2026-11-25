// U-12 / U-13 console section 2: the `Signature` message (accept/reject through `Signature.fromProtoV30` and
// `CryptoPureApi.verifySignature`).
// Appended after u12-keys.scala (it uses that file's helpers `u_bs`, `u_res`, `u_fix`, `u_mut`, `u_order`, `u_specs`, ...).
//
// Output lines:
//   sg   <label>/<case>  <public key: v30.SigningPublicKey bytes>  <hash multihash>  <usage name>  <v30.Signature bytes>
//        <OK|PARSE|VERIFY|THROW>  <class>  <detail>
//        PARSE = `Signature.fromProtoV30` refused the message, VERIFY = `verifySignature` refused it, OK = accepted.
import com.digitalasset.nonempty.NonEmpty

val u_h2 = pure.digest(HashPurpose.SequencedEventSignature, ByteString.copyFromUtf8("another message"))
val u_usages: List[(String, NonEmpty[Set[SigningKeyUsage]])] = List(
  ("protocol", SigningKeyUsage.ProtocolOnly), ("namespace", SigningKeyUsage.NamespaceOnly),
  ("sequencerAuth", SigningKeyUsage.SequencerAuthenticationOnly), ("all", SigningKeyUsage.All))

def u_sgTrial(label: String, n: String, pk: SigningPublicKey, h: Hash, useName: String, use: NonEmpty[Set[SigningKeyUsage]], s: cv30.Signature): Unit = {
  CryptoKeyValidation.clearValidationCaches()
  val parsed = scala.util.Try(Signature.fromProtoV30(s))
  val (ok, cls, detail) = parsed match {
    case scala.util.Success(Left(e)) => ("PARSE", u_cls(e), u_norm(e.toString))
    case scala.util.Failure(t) => ("THROW", u_cls(t), u_norm(String.valueOf(t.getMessage)))
    case scala.util.Success(Right(sig)) =>
      scala.util.Try(pure.verifySignature(h, pk, sig, use)) match {
        case scala.util.Success(Right(_)) => ("OK", "-", "-")
        case scala.util.Success(Left(e)) => ("VERIFY", u_cls(e), u_norm(e.toString))
        case scala.util.Failure(t) => ("THROW", u_cls(t), u_norm(String.valueOf(t.getMessage)))
      }
  }
  println(List("ORA sg", label + "/" + n, hex(pk.toProtoV30.toOption.get.toByteString), hex(h.getCryptographicEvidence), useName, hex(s.toByteString), ok, cls, detail).mkString("\t"))
}

val u_sgKeys = u_specs.map { case (label, spec, specNum) =>
  val pk = p1.keys.secret.generate_signing_key("u12-sg-" + label, usage, Some(spec))
  val kp = CryptoKeyPair.fromTrustedByteString(p1.keys.secret.download(pk.fingerprint)).toOption.get.asInstanceOf[SigningKeyPair]
  (label, pk, kp)
}

def u_intRaw(b: Array[Byte]): Array[Byte] = Array[Byte](0x02, b.length.toByte) ++ b
def u_seqRaw(c: Array[Byte]): Array[Byte] = Array[Byte](0x30, c.length.toByte) ++ c
def u_derOf(r: BigInteger, s: BigInteger): Array[Byte] = new DERSequence(Array[ASN1Encodable](new ASN1Integer(r), new ASN1Integer(s))).getEncoded

u_sgKeys.foreach { case (label, pk, kp) =>
  val sig = pure.sign(u_hash, kp.privateKey, usage).toOption.get
  val sp = sig.toProtoV30
  val sb = sp.signature.toByteArray
  def fmt(n: Int) = cv30.SignatureFormat.fromValue(n)
  def spc(n: Int) = cv30.SigningAlgorithmSpec.fromValue(n)
  def wb(b: Array[Byte]) = sp.copy(signature = u_bs(b))
  def t(n: String, s: cv30.Signature, h: Hash = u_hash, useName: String = "protocol", use: NonEmpty[Set[SigningKeyUsage]] = usage, key: SigningPublicKey = pk): Unit =
    u_sgTrial(label, n, key, h, useName, use, s)
  t("valid", sp)
  u_usages.foreach { case (un, u) => t("usage-" + un, sp, useName = un, use = u) }
  t("otherHash", sp, h = u_h2)
  u_sgKeys.filter(_._1 != label).foreach { case (l2, pk2, _) => t("underKey" + l2, sp, key = pk2) }
  (0 to 5).foreach(n => t("format" + n, sp.copy(format = fmt(n))))
  t("formatSymbolic", sp.copy(format = fmt(10000))); t("formatUnknown99", sp.copy(format = fmt(99)))
  (0 to 4).foreach(n => t("spec" + n, sp.copy(signingAlgorithmSpec = spc(n)))); t("spec99", sp.copy(signingAlgorithmSpec = spc(99)))
  t("rawFormatNoSpec", sp.copy(format = fmt(1), signingAlgorithmSpec = spc(0)))
  t("derFormatNoSpec", sp.copy(format = fmt(2), signingAlgorithmSpec = spc(0)))
  t("concatFormatNoSpec", sp.copy(format = fmt(3), signingAlgorithmSpec = spc(0)))
  t("signedByEmpty", sp.copy(signedBy = "")); t("signedByOtherKey", sp.copy(signedBy = u_sgKeys.filter(_._1 != label).head._2.fingerprint.unwrap))
  // which check fires first when two things are wrong at once (the order in JcePureCrypto.verifySignature)
  val otherId = u_sgKeys.filter(_._1 != label).head._2.fingerprint.unwrap
  t("wrongKeyAndSpec", sp.copy(signedBy = otherId, signingAlgorithmSpec = spc(1)))
  t("specAndUsage", sp.copy(signingAlgorithmSpec = spc(if (label == "Ed25519") 2 else 1)), useName = "namespace", use = SigningKeyUsage.NamespaceOnly)
  t("usageAndFormat", sp.copy(format = fmt(if (label == "Ed25519") 2 else 3)), useName = "namespace", use = SigningKeyUsage.NamespaceOnly)
  t("formatAndBadSignature", sp.copy(format = fmt(if (label == "Ed25519") 2 else 3), signature = u_bs(u_mut(sb, 0))))
  t("noSpecAndUsage", sp.copy(signingAlgorithmSpec = spc(0)), useName = "namespace", use = SigningKeyUsage.NamespaceOnly)
  t("signedByInvalidChars", sp.copy(signedBy = "bad!id")); t("signedByLong80", sp.copy(signedBy = "a" * 80))
  if (label == "Ed25519") {
    val l = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")
    val sInt = new BigInteger(1, sb.slice(32, 64).reverse)
    def le(v: BigInteger) = u_fix(v, 32).reverse
    val r = new BigInteger(1, sb.slice(0, 32).reverse)
    t("flipR", wb(u_mut(sb, 0))); t("flipSLow", wb(u_mut(sb, 32))); t("flipSHigh", wb(u_mut(sb, 63)))
    t("sPlusL", wb(sb.take(32) ++ le(sInt.add(l)))); t("sEqualsL", wb(sb.take(32) ++ le(l))); t("sZero", wb(sb.take(32) ++ Array.fill[Byte](32)(0)))
    t("sMinusL", wb(sb.take(32) ++ le(l.subtract(BigInteger.ONE))))
    t("rZero", wb(Array.fill[Byte](32)(0) ++ sb.drop(32))); t("allZero", wb(Array.fill[Byte](64)(0)))
    t("len63", wb(sb.dropRight(1))); t("len65", wb(sb :+ 0.toByte)); t("empty", wb(Array.empty[Byte])); t("len128", wb(sb ++ sb))
    t("derEncoded", sp.copy(signature = u_bs(u_derOf(r, sInt)), format = fmt(2), signingAlgorithmSpec = spc(2)))
    t("derBytesConcatFormat", wb(u_derOf(r, sInt)))
  } else {
    val seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(sb)
    val r = org.bouncycastle.asn1.ASN1Integer.getInstance(seq.getObjectAt(0)).getValue
    val s = org.bouncycastle.asn1.ASN1Integer.getInstance(seq.getObjectAt(1)).getValue
    val n = u_order(label)
    val len = (n.bitLength + 7) / 8
    val content = u_intRaw(r.toByteArray) ++ u_intRaw(s.toByteArray)
    t("highS", wb(u_derOf(r, n.subtract(s))))
    t("rZero", wb(u_derOf(BigInteger.ZERO, s))); t("sZero", wb(u_derOf(r, BigInteger.ZERO)))
    t("rEqualsN", wb(u_derOf(n, s))); t("sEqualsN", wb(u_derOf(r, n)))
    t("rPlusN", wb(u_derOf(r.add(n), s))); t("sPlusN", wb(u_derOf(r, s.add(n))))
    t("rNegative", wb(u_derOf(r.negate(), s))); t("sOne", wb(u_derOf(r, BigInteger.ONE))); t("rOneSOne", wb(u_derOf(BigInteger.ONE, BigInteger.ONE)))
    t("swapped", wb(u_derOf(s, r)))
    t("rUnpadHighBit", wb(u_seqRaw(u_intRaw(setAt(u_fix(r, len), 0, u_fix(r, len)(0) | 0x80)) ++ u_intRaw(s.toByteArray))))
    t("rPadded", wb(u_seqRaw(u_intRaw(Array[Byte](0) ++ r.toByteArray) ++ u_intRaw(s.toByteArray))))
    t("sPadded", wb(u_seqRaw(u_intRaw(r.toByteArray) ++ u_intRaw(Array[Byte](0) ++ s.toByteArray))))
    t("longFormLength", wb(Array[Byte](0x30, 0x81.toByte, content.length.toByte) ++ content))
    t("indefiniteLength", wb(Array[Byte](0x30, 0x80.toByte) ++ content ++ Array[Byte](0, 0)))
    t("trailingByte", wb(sb :+ 0.toByte)); t("trailingNull", wb(sb ++ Array[Byte](5, 0)))
    t("truncated", wb(sb.dropRight(1))); t("dropFirst", wb(sb.drop(1)))
    t("extraInteger", wb(u_seqRaw(content ++ u_intRaw(Array[Byte](1))))); t("oneInteger", wb(u_seqRaw(u_intRaw(r.toByteArray))))
    t("rAsOctetString", wb(u_seqRaw(Array[Byte](0x04, r.toByteArray.length.toByte) ++ r.toByteArray ++ u_intRaw(s.toByteArray))))
    t("concatRaw", wb(u_fix(r, len) ++ u_fix(s, len)))
    t("concatRawConcatFormat", wb(u_fix(r, len) ++ u_fix(s, len)).copy(format = fmt(3)))
    t("empty", wb(Array.empty[Byte])); t("zeros70", wb(Array.fill[Byte](70)(0))); t("flipMid", wb(u_mut(sb, sb.length / 2)))
    t("otherMessageSignature", pure.sign(u_h2, kp.privateKey, usage).toOption.get.toProtoV30)
  }
}
