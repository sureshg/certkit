package certkit.cert

import certkit.pem.*
import certkit.tls.trustManagers
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import javax.security.auth.x500.X500Principal
import kotlin.test.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toInstant

class CertTest {

  @Test
  fun `buildSelfSigned produces a valid self-signed CA certificate`() {
    val keyPair = genECKeyPair()
    val subject = X500Principal("CN=Test,O=TestOrg")
    val now = Clock.System.now()
    val cert =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            serialNumber = 1,
            issuer = subject,
            subject = subject,
            notBefore = now - 1.days,
            notAfter = now + 1.days,
            sans = listOf(San.Dns("localhost"), San.Ip("127.0.0.1")),
        )

    assertTrue(cert.selfSigned)
    assertTrue(cert.isCA)
    assertFalse(cert.isIntermediateCA)
  }

  @Test
  fun `buildSelfSigned sets certificate fields correctly`() {
    val keyPair = genECKeyPair()
    val issuer = X500Principal("CN=issuer,O=TestOrg")
    val subject = X500Principal("CN=subject,O=TestOrg")
    val now = Clock.System.now()
    val yesterday = now - 1.days
    val tomorrow = now + 1.days
    val cert =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            serialNumber = 12345,
            issuer = issuer,
            subject = subject,
            notBefore = yesterday,
            notAfter = tomorrow,
        )

    assertEquals(BigInteger.valueOf(12345), cert.serialNumber)
    assertEquals(issuer, cert.issuerX500Principal)
    assertEquals(subject, cert.subjectX500Principal)
    assertEquals(keyPair.public, cert.publicKey)

    // X.509 UTCTime has only second-level precision
    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.1
    assertEquals(
        yesterday.epochSeconds,
        cert.startDateUtc.toInstant(TimeZone.UTC).epochSeconds,
    )
    assertEquals(
        tomorrow.epochSeconds,
        cert.expiryDateUtc.toInstant(TimeZone.UTC).epochSeconds,
    )
    assertFalse(cert.isExpired)
    assertTrue(cert.expiresIn in 0.days..2.days)
  }

  @Test
  fun `buildSelfSigned includes extensions`() {
    val keyPair = genECKeyPair()
    val subject = X500Principal("CN=Test User,O=TestOrg")
    val now = Clock.System.now()
    val cert =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            issuer = subject,
            subject = subject,
            notBefore = now - 1.days,
            notAfter = now + 1.days,
            sans = listOf(San.Dns("example.com")),
        )

    assertEquals("Test User", cert.commonName)
    assertTrue(cert.isCA)
  }

  @Test
  fun `buildSelfSigned certificate is trusted in a trust store`() {
    val keyPair = genECKeyPair()
    val subject = X500Principal("CN=Trust Test")
    val now = Clock.System.now()
    val cert =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            issuer = subject,
            subject = subject,
            notBefore = now - 1.days,
            notAfter = now + 1.days,
        )

    val keyStore =
        KeyStore.getInstance(KeyStore.getDefaultType()).apply {
          load(null, null)
          setCertificateEntry("test", cert)
        }
    keyStore.trustManagers.forEach { it.checkServerTrusted(arrayOf(cert), "EC") }
  }

  @Test
  fun `certificate PEM round-trip`() {
    val keyPair = genECKeyPair()
    val subject = X500Principal("CN=RoundTrip")
    val now = Clock.System.now()
    val cert =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            issuer = subject,
            subject = subject,
            notBefore = now - 1.days,
            notAfter = now + 1.days,
        )

    val parsed = Pem.readCertificateChain(cert.pem).single()
    assertEquals(cert, parsed)
  }

  @Test
  fun `key pair PEM encoding`() {
    val keyPair = genECKeyPair()

    assertTrue(keyPair.public.pem.startsWith("-----BEGIN PUBLIC KEY-----"))
    assertTrue(keyPair.private.pem.startsWith("-----BEGIN PRIVATE KEY-----"))
  }

  private fun genECKeyPair(): KeyPair =
      KeyPairGenerator.getInstance("EC")
          .apply { initialize(ECGenParameterSpec("secp256r1")) }
          .generateKeyPair()
}
