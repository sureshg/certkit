package certkit.csr

import certkit.cert.San
import certkit.der.Der
import java.security.PublicKey
import javax.security.auth.x500.X500Principal

/** An immutable PKCS#10 Certificate Signing Request. */
public class CsrRequest(
    public val info: CsrInfo,
    public val algorithm: SignatureAlgo,
    public val signature: ByteArray,
) {
  public val encoded: ByteArray =
      Der.sequence(info.encoded, Der.sequence(algorithm.encoded), Der.bitString(0, signature))

  override fun equals(other: Any?): Boolean =
      this === other || (other is CsrRequest && encoded.contentEquals(other.encoded))

  override fun hashCode(): Int = encoded.contentHashCode()

  override fun toString(): String = "CsrRequest(info=$info, algorithm=$algorithm)"
}

/**
 * Signature algorithm (name + OID) resolved from JCA security providers. Equality is by OID only.
 */
public class SignatureAlgo(public val name: String, public val oid: String) {
  public val encoded: ByteArray = Der.oid(oid)

  override fun equals(other: Any?): Boolean = this === other || (other is SignatureAlgo && oid == other.oid)

  override fun hashCode(): Int = oid.hashCode()

  override fun toString(): String = "SignatureAlgo(name=$name, oid=$oid)"
}

/** PKCS#10 CSR info: subject name + public key + optional SANs, DER-encoded per RFC 2986 §4.1. */
public data class CsrInfo(
    public val subject: X500Principal,
    public val publicKey: PublicKey,
    public val sans: List<San> = emptyList(),
) {

  private companion object {
    /** DER-encoded INTEGER 0 — CSR version v1. */
    val VERSION_0: ByteArray = byteArrayOf(2, 1, 0)

    /** Empty context-specific constructed tag [0] with zero length. */
    val EMPTY_ATTRIBUTES: ByteArray = byteArrayOf(0xA0.toByte(), 0x00)

    /** OID for PKCS#9 extensionRequest attribute. */
    const val EXTENSION_REQUEST_OID = "1.2.840.113549.1.9.14"

    /** OID for X.509 subjectAltName extension. */
    const val SUBJECT_ALT_NAME_OID = "2.5.29.17"
  }

  public val encoded: ByteArray
    get() =
        Der.sequence(
            VERSION_0,
            subject.encoded,
            publicKey.encoded,
            encodeAttributes(),
        )

  private fun encodeAttributes() =
      when {
        sans.isEmpty() -> EMPTY_ATTRIBUTES
        else -> {
          val sanEntries = sans.map { it.toDer() }
          val sanExtension =
              Der.sequence(
                  Der.oid(SUBJECT_ALT_NAME_OID),
                  Der.octetString(Der.sequence(*sanEntries.toTypedArray())),
              )
          val extRequest =
              Der.sequence(
                  Der.oid(EXTENSION_REQUEST_OID),
                  Der.set(Der.sequence(sanExtension)),
              )
          Der.explicitTag(0, extRequest)
        }
      }
}
