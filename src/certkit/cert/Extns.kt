package certkit.cert

import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import java.security.cert.*
import javax.naming.ldap.LdapName
import kotlin.time.Instant

/** Returns the subject common name (CN) from the certificate's distinguished name. */
val X509Certificate.commonName: String
  get() =
      LdapName(subjectX500Principal.name)
          .rdns
          .filter { it.type.equals("CN", ignoreCase = true) }
          .map { it.value.toString() }
          .single()

/**
 * Returns the subject alternative names (RFC822/email, DNS, and IP address types).
 *
 * SAN type OIDs: 1 = RFC822/email, 2 = DNS, 7 = IP address.
 */
val X509Certificate.subjectAltNames: List<String>
  get() =
      subjectAlternativeNames
          .orEmpty()
          .filter { it.size == 2 }
          .mapNotNull {
            when (it[0].toString().toInt()) {
              1,
              2,
              7 -> it[1].toString()
              else -> null
            }
          }

/** Returns `true` if this certificate is signed by the given [ca] certificate. */
fun X509Certificate.signedBy(ca: X509Certificate): Boolean =
    issuerX500Principal == ca.subjectX500Principal && runCatching { verify(ca.publicKey) }.isSuccess

/** Returns `true` if this certificate is self-signed. */
val X509Certificate.selfSigned: Boolean
  get() = signedBy(this)

/**
 * Returns `true` if this certificate is a CA.
 *
 * Checks two sources (either is sufficient):
 * - **Basic Constraints** extension (`2.5.29.19`): `basicConstraints >= 0` means `cA: TRUE`.
 *   Returns `-1` for end-entity certs, or the path-length constraint (≥ 0) for CA certs.
 * - **Key Usage** extension (`2.5.29.15`): bit 5 = `keyCertSign`.
 *
 * Self-signed certs often include only Basic Constraints without Key Usage.
 */
val X509Certificate.isCA: Boolean
  get() = basicConstraints >= 0 || keyUsage?.get(5) == true

/** Returns `true` if this certificate is an intermediate CA (CA but not self-signed). */
val X509Certificate.isIntermediateCA: Boolean
  get() = isCA && !selfSigned

/** Returns the certificate expiry date/time in UTC. */
val X509Certificate.expiryDateUTC
  get() = Instant.fromEpochMilliseconds(notAfter.time).toLocalDateTime(TimeZone.UTC)

/**
 * Returns `true` if this certificate chain is signed by one of the given [root] CA certificates.
 */
fun List<X509Certificate>.isSignedByRoot(root: List<X509Certificate>): Boolean {
  check(isNotEmpty()) { "Cert chain is empty" }
  val trustAnchors = root.map { TrustAnchor(it, null) }.toSet()
  val params = PKIXParameters(trustAnchors).apply { isRevocationEnabled = false }
  val certPath = CertificateFactory.getInstance("X.509").generateCertPath(this)
  return runCatching { CertPathValidator.getInstance("PKIX").validate(certPath, params) }.isSuccess
}
