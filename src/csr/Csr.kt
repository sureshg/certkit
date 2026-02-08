package dev.suresh.certkit.csr

import dev.suresh.certkit.der.Der
import dev.suresh.certkit.pem.*
import java.security.*
import javax.security.auth.x500.X500Principal

// PKCS#10 CSR version 0 and empty attributes DER constants
private val VERSION_0 = byteArrayOf(2, 1, 0)
private val EMPTY_ATTRIBUTES = byteArrayOf(0xA0.toByte(), 0)

/** PKCS#10 CSR factory and signature algorithm discovery. */
object Csr {

  private const val SIGNATURE_OID_PREFIX = "Alg.Alias.Signature.OID."

  private val signatureAlgorithms: Map<String, SignatureAlgorithmId> by lazy {
    buildMap {
      Security.getProviders()
          .flatMap { it.entries }
          .filter { it.key.toString().startsWith(SIGNATURE_OID_PREFIX) }
          .forEach { entry ->
            val name = entry.value.toString()
            val oid = entry.key.toString().removePrefix(SIGNATURE_OID_PREFIX)
            putIfAbsent(name, SignatureAlgorithmId(name, oid))
          }
    }
  }

  /** Returns all signature algorithms discovered from JCA security providers. */
  fun allSignatureAlgorithms(): Map<String, SignatureAlgorithmId> = signatureAlgorithms

  /** Finds a signature algorithm by JCA name (e.g. "SHA256withRSA"). */
  fun findSignatureAlgorithm(name: String): SignatureAlgorithmId {
    require(name in signatureAlgorithms) { "Unknown signature algorithm '$name'" }
    return signatureAlgorithms.getValue(name)
  }

  /** Creates a CSR from an X.500 name string, signature algorithm name, and key pair. */
  fun create(
      x500Name: String,
      signatureAlgorithm: String,
      keyPair: KeyPair,
  ): CertificationRequest {
    val info = CertificationRequestInfo(X500Principal(x500Name), keyPair.public)
    val algorithmId = findSignatureAlgorithm(signatureAlgorithm)
    return CertificationRequest(info, algorithmId, info.sign(algorithmId, keyPair.private))
  }

  /** Creates a CSR by signing the given [info] with the [privateKey]. */
  fun create(
      info: CertificationRequestInfo,
      algorithmId: SignatureAlgorithmId,
      privateKey: PrivateKey,
  ): CertificationRequest =
      CertificationRequest(info, algorithmId, info.sign(algorithmId, privateKey))

  /** Creates a CSR from a pre-computed [signature]. */
  fun create(
      info: CertificationRequestInfo,
      algorithmId: SignatureAlgorithmId,
      signature: ByteArray,
  ): CertificationRequest = CertificationRequest(info, algorithmId, signature.copyOf())
}

/**
 * Signature algorithm identifier resolved from JCA security providers.
 *
 * Equality is based on [oid] only, matching the original Java semantics.
 */
class SignatureAlgorithmId(val name: String, val oid: String) {
  val encoded: ByteArray = Der.oid(oid)

  override fun equals(other: Any?) =
      this === other || (other is SignatureAlgorithmId && oid == other.oid)

  override fun hashCode() = oid.hashCode()

  override fun toString() = "SignatureAlgorithmId(name=$name, oid=$oid)"
}

/** PKCS#10 certification request info (subject + public key). */
data class CertificationRequestInfo(val subject: X500Principal, val publicKey: PublicKey) {

  val encoded: ByteArray =
      Der.sequence(VERSION_0, subject.encoded, publicKey.encoded, EMPTY_ATTRIBUTES)

  /** Signs this request info with the given [privateKey] and returns the raw signature bytes. */
  fun sign(algorithmId: SignatureAlgorithmId, privateKey: PrivateKey): ByteArray =
      Signature.getInstance(algorithmId.name)
          .apply {
            initSign(privateKey)
            update(encoded)
          }
          .sign()
}

/**
 * PKCS#10 certification request (CSR).
 *
 * Not a `data class` because [signature] is a `ByteArray` (needs `contentEquals`).
 */
class CertificationRequest(
    val info: CertificationRequestInfo,
    val algorithmId: SignatureAlgorithmId,
    val signature: ByteArray,
) {
  val encoded: ByteArray =
      Der.sequence(info.encoded, Der.sequence(algorithmId.encoded), Der.bitString(0, signature))

  val pemEncoded: String = encoded.encodePem(PemType.X509_REQ)

  override fun equals(other: Any?) =
      this === other || (other is CertificationRequest && encoded.contentEquals(other.encoded))

  override fun hashCode() = encoded.contentHashCode()

  override fun toString() = "CertificationRequest(info=$info, algorithmId=$algorithmId)"
}
