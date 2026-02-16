package certkit.crl

import certkit.cert.Cert
import certkit.pem.pem
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import javax.security.auth.x500.X500Principal
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

class CrlTest {

  companion object {
    private val now = Clock.System.now()
    private val caKey = ecKeyPair()
    private val leafKey = ecKeyPair()
    private val otherKey = ecKeyPair()
    private val CA = X500Principal("CN=Test CA")

    private val caCert: X509Certificate =
        Cert.buildSelfSigned(
            keyPair = caKey,
            issuer = CA,
            subject = CA,
            notBefore = now - 1.days,
            notAfter = now + 365.days,
        )

    private val leafCert: X509Certificate =
        Cert.buildSelfSigned(
            keyPair = leafKey,
            serialNumber = 2,
            issuer = CA,
            subject = X500Principal("CN=Leaf"),
            notBefore = now - 1.days,
            notAfter = now + 365.days,
        )

    private val crl: X509CRL =
        Crl.build(
            keyPair = caKey,
            issuer = CA,
            thisUpdate = now,
            nextUpdate = now + 30.days,
            revokedSerials = listOf(2L, 42L),
        )

    private val expiredCrl: X509CRL =
        Crl.build(
            keyPair = caKey,
            issuer = CA,
            thisUpdate = now - 60.days,
            nextUpdate = now - 30.days,
            revokedSerials = listOf(2L),
        )

    private fun ecKeyPair() =
        KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
  }

  @Test fun `from PEM round-trips`() = assertEquals(crl, Crl.from(crl.pem))

  @Test fun `from DER round-trips`() = assertEquals(crl, Crl.from(crl.encoded))

  @Test fun `issuerCN returns common name`() = assertEquals("Test CA", crl.issuerCN)

  @Test
  fun `isSignedBy verifies CA signature`() {
    assertTrue(crl.isSignedBy(caCert))
    val otherCa =
        Cert.buildSelfSigned(
            keyPair = otherKey,
            issuer = X500Principal("CN=Other"),
            subject = X500Principal("CN=Other"),
            notBefore = now - 1.days,
            notAfter = now + 365.days,
        )
    assertFalse(crl.isSignedBy(otherCa))
  }

  @Test
  fun `contains and isRevokedBy check revocation`() {
    assertTrue(leafCert in crl)
    assertFalse(caCert in crl)
    assertTrue(leafCert.isRevokedBy(crl))
    assertFalse(caCert.isRevokedBy(crl))
  }

  @Test
  fun `pem produces valid PEM block`() {
    assertTrue(crl.pem.startsWith("-----BEGIN X509 CRL-----"))
    assertTrue(crl.pem.endsWith("-----END X509 CRL-----\n"))
  }
}
