package certkit.cert

import certkit.der.*
import java.security.KeyPair
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import javax.security.auth.x500.X500Principal
import kotlin.time.Instant
import kotlinx.datetime.*

/**
 * Self-signed X.509 certificate builder (EC keys, SHA256withECDSA).
 *
 * Constructs a DER-encoded X.509v3 certificate ([RFC
 * 5280](https://datatracker.ietf.org/doc/html/rfc5280)):
 * ```
 * Certificate ::= SEQUENCE {
 *   tbsCertificate     SEQUENCE {
 *     version          [0] INTEGER (v3=2),
 *     serialNumber     INTEGER,
 *     signature        AlgorithmIdentifier (SHA256withECDSA),
 *     issuer           Name,
 *     validity         SEQUENCE { notBefore UTCTime, notAfter UTCTime },  -- second precision only
 *     subject          Name,
 *     subjectPublicKey SubjectPublicKeyInfo,
 *     extensions       [3] SEQUENCE {
 *       subjectKeyId, authorityKeyId, basicConstraints, subjectAltName
 *     }
 *   },
 *   signatureAlgorithm AlgorithmIdentifier,
 *   signatureValue     BIT STRING
 * }
 * ```
 */
public object Cert {

  private val SHA256_ECDSA_OID = Der.oid("1.2.840.10045.4.3.2")
  private val SUBJECT_KEY_ID_OID = Der.oid("2.5.29.14")
  private val AUTHORITY_KEY_ID_OID = Der.oid("2.5.29.35")
  private val BASIC_CONSTRAINTS_OID = Der.oid("2.5.29.19")
  private val SUBJECT_ALT_NAME_OID = Der.oid("2.5.29.17")

  private val certFactory = CertificateFactory.getInstance("X.509")

  /**
   * Builds a self-signed X.509v3 certificate. The [keyPair] must be EC (P-256/P-384/P-521).
   *
   * **Note:** [notBefore] and [notAfter] are encoded as ASN.1 UTCTime, which has only whole-second
   * precision ([RFC 5280
   * §4.1.2.5.1](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.1)). Any sub-second
   * component is silently truncated.
   */
  public fun buildSelfSigned(
      keyPair: KeyPair,
      serialNumber: Long = 0,
      issuer: X500Principal,
      subject: X500Principal,
      notBefore: Instant,
      notAfter: Instant,
      sans: List<San> = emptyList(),
  ): X509Certificate {
    val pub = keyPair.public
    val priv = keyPair.private
    require(pub is ECPublicKey) { "not an EC public key: $pub" }
    require(priv is ECPrivateKey) { "not an EC private key: $priv" }
    require(serialNumber >= 0) { "serialNumber is negative" }
    require(notBefore <= notAfter) { "notAfter is before notBefore" }

    val pubKeyHash = hashPublicKey(pub)
    val sigAlg = Der.sequence(SHA256_ECDSA_OID, Der.nullValue)

    val rawCert = seq {
      explicitTag(0) { integer(2L) }
      integer(serialNumber)
      raw(sigAlg)
      raw(issuer.encoded)
      seq {
        utcTime(notBefore)
        utcTime(notAfter)
      }
      raw(subject.encoded)
      raw(pub.encoded)
      explicitTag(3) {
        seq {
          seq {
            raw(SUBJECT_KEY_ID_OID)
            octetString { octetString(pubKeyHash) }
          }
          seq {
            raw(AUTHORITY_KEY_ID_OID)
            octetString { seq { implicitTag(0, pubKeyHash) } }
          }
          seq {
            raw(BASIC_CONSTRAINTS_OID)
            boolean(true)
            octetString { seq { boolean(true) } }
          }
          seq {
            raw(SUBJECT_ALT_NAME_OID)
            octetString { seq { sans.forEach { raw(it.toDer()) } } }
          }
        }
      }
    }

    val sig =
        Signature.getInstance("SHA256withECDSA")
            .apply {
              initSign(priv)
              update(rawCert)
            }
            .sign()

    val encoded = seq {
      raw(rawCert)
      raw(sigAlg)
      bitString(0, sig)
    }
    return certFactory.generateCertificate(encoded.inputStream()) as X509Certificate
  }

  /** Convenience overload that accepts [LocalDate] instead of [Instant]. */
  public fun buildSelfSigned(
      keyPair: KeyPair,
      serialNumber: Long = 0,
      issuer: X500Principal,
      subject: X500Principal,
      notBefore: LocalDate,
      notAfter: LocalDate,
      sans: List<San> = emptyList(),
  ): X509Certificate =
      buildSelfSigned(
          keyPair = keyPair,
          serialNumber = serialNumber,
          issuer = issuer,
          subject = subject,
          notBefore = notBefore.atStartOfDayIn(TimeZone.UTC),
          // Converts the LocalDate to the last second of that day in UTC (23:59:59 UTC)
          notAfter = notAfter.atTime(23, 59, 59).toInstant(TimeZone.UTC),
          sans = sans,
      )

  public fun hashPublicKey(key: ECPublicKey): ByteArray {
    val raw = Der.sequence(Der.integer(key.w.affineX), Der.integer(key.w.affineY))
    return MessageDigest.getInstance("SHA-1").digest(raw)
  }
}
