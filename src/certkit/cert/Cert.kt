@file:OptIn(kotlin.time.ExperimentalTime::class)

package certkit.cert

import certkit.der.Der
import kotlinx.datetime.*
import java.net.InetAddress
import java.security.KeyPair
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import javax.security.auth.x500.X500Principal
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/** Self-signed X.509 certificate builder (EC keys only). */
object Cert {

  private val SHA256_ECDSA_OID = Der.oid("1.2.840.10045.4.3.2")
  private val SUBJECT_KEY_ID_OID = Der.oid("2.5.29.14")
  private val AUTHORITY_KEY_ID_OID = Der.oid("2.5.29.35")
  private val BASIC_CONSTRAINTS_OID = Der.oid("2.5.29.19")
  private val SUBJECT_ALT_NAME_OID = Der.oid("2.5.29.17")

  /** Builds a self-signed X.509 certificate using the given EC [keyPair] and subject details. */
  fun buildSelfSigned(
      keyPair: KeyPair,
      serialNumber: Long = 0,
      issuer: X500Principal,
      subject: X500Principal,
      notBefore: Instant,
      notAfter: Instant,
      sanDnsNames: List<String> = emptyList(),
      sanIpAddresses: List<InetAddress> = emptyList(),
  ): X509Certificate {
    val pub = keyPair.public
    val priv = keyPair.private
    require(pub is ECPublicKey) { "not an EC public key: $pub" }
    require(priv is ECPrivateKey) { "not an EC private key: $priv" }
    require(serialNumber >= 0) { "serialNumber is negative" }
    require(notBefore <= notAfter) { "notAfter is before notBefore" }

    val pubKeyHash = hashPublicKey(pub)
    val sans = buildList {
      sanDnsNames.forEach { add(Der.contextTag(2, it.encodeToByteArray())) }
      sanIpAddresses.forEach { add(Der.contextTag(7, it.address)) }
    }

    val sigAlg = Der.sequence(SHA256_ECDSA_OID, Der.derNull())

    val rawCert =
        Der.sequence(
            Der.contextSequence(0, Der.integer(2)),
            Der.integer(serialNumber),
            sigAlg,
            issuer.encoded,
            Der.sequence(Der.utcTime(notBefore), Der.utcTime(notAfter)),
            subject.encoded,
            pub.encoded,
            Der.contextSequence(
                3,
                Der.sequence(
                    Der.sequence(SUBJECT_KEY_ID_OID, Der.octetString(Der.octetString(pubKeyHash))),
                    Der.sequence(
                        AUTHORITY_KEY_ID_OID,
                        Der.octetString(Der.sequence(Der.contextTag(0, pubKeyHash))),
                    ),
                    Der.sequence(
                        BASIC_CONSTRAINTS_OID,
                        Der.booleanTrue(),
                        Der.octetString(Der.sequence(Der.booleanTrue())),
                    ),
                    Der.sequence(
                        SUBJECT_ALT_NAME_OID,
                        Der.octetString(Der.sequence(*sans.toTypedArray())),
                    ),
                ),
            ),
        )

    val sig =
        Signature.getInstance("SHA256withECDSA")
            .apply {
              initSign(priv)
              update(rawCert)
            }
            .sign()

    val encoded = Der.sequence(rawCert, sigAlg, Der.bitString(0, sig))
    return CertificateFactory.getInstance("X.509").generateCertificate(encoded.inputStream())
        as X509Certificate
  }

  /** Convenience overload accepting [LocalDate] for notBefore/notAfter. */
  fun buildSelfSigned(
      keyPair: KeyPair,
      serialNumber: Long = 0,
      issuer: X500Principal,
      subject: X500Principal,
      notBefore: LocalDate,
      notAfter: LocalDate,
      sanDnsNames: List<String> = emptyList(),
      sanIpAddresses: List<InetAddress> = emptyList(),
  ): X509Certificate =
      buildSelfSigned(
          keyPair = keyPair,
          serialNumber = serialNumber,
          issuer = issuer,
          subject = subject,
          notBefore = notBefore.atStartOfDayIn(TimeZone.UTC),
          notAfter = notAfter.plus(1, DateTimeUnit.DAY).atStartOfDayIn(TimeZone.UTC) - 1.seconds,
          sanDnsNames = sanDnsNames,
          sanIpAddresses = sanIpAddresses,
      )

  private fun hashPublicKey(key: ECPublicKey): ByteArray {
    val raw = Der.sequence(Der.integer(key.w.affineX), Der.integer(key.w.affineY))
    return MessageDigest.getInstance("SHA-1").digest(raw)
  }
}
