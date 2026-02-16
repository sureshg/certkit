package certkit.crl

import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import javax.naming.ldap.LdapName

/** Returns the issuer common name (CN) from the CRL's issuer distinguished name. */
val X509CRL.issuerCN: String
  get() =
      LdapName(issuerX500Principal.name)
          .rdns
          .filter { it.type.equals("CN", ignoreCase = true) }
          .map { it.value.toString() }
          .single()

/** Returns `true` if this CRL was signed by the given [ca] certificate. */
fun X509CRL.isSignedBy(ca: X509Certificate): Boolean =
    issuerX500Principal == ca.subjectX500Principal && runCatching { verify(ca.publicKey) }.isSuccess

/** Returns `true` if the given [cert] is revoked in this CRL. */
operator fun X509CRL.contains(cert: X509Certificate): Boolean = isRevoked(cert)

/** Returns `true` if this certificate is revoked per the given [crl]. */
fun X509Certificate.isRevokedBy(crl: X509CRL): Boolean = crl.isRevoked(this)
