package certkit.cert

import certkit.pem.Pem
import certkit.pem.pem
import certkit.tls.trustManagers
import kotlinx.datetime.LocalDate
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CertTest {

  @Test
  fun `buildSelfSigned produces a valid self-signed CA certificate`() {
    val keyPair = genECKeyPair()
    val subject = X500Principal("CN=Test,O=Test Org")
    val cert =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            serialNumber = 1,
            issuer = subject,
            subject = subject,
            notBefore = LocalDate(2024, 1, 1),
            notAfter = LocalDate(2025, 12, 31),
            sans = listOf(San.Dns("localhost"), San.Ip("127.0.0.1")),
        )

    assertTrue(cert.selfSigned)
    assertTrue(cert.isCA)
    assertFalse(cert.isIntermediateCA)
  }

  @Test
  fun `buildSelfSigned sets certificate fields correctly`() {
    val keyPair = genECKeyPair()
    val issuer = X500Principal("CN=issuer,O=Airlift")
    val subject = X500Principal("CN=subject,O=Airlift")
    val cert =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            serialNumber = 12345,
            issuer = issuer,
            subject = subject,
            notBefore = LocalDate(2024, 1, 1),
            notAfter = LocalDate(2025, 12, 31),
        )

    assertEquals(BigInteger.valueOf(12345), cert.serialNumber)
    assertEquals(issuer, cert.issuerX500Principal)
    assertEquals(subject, cert.subjectX500Principal)
    assertEquals(keyPair.public, cert.publicKey)
    assertEquals("2024-01-01T00:00:00Z", cert.notBefore.toInstant().toString())
    assertEquals("2025-12-31T23:59:59Z", cert.notAfter.toInstant().toString())
  }

  @Test
  fun `buildSelfSigned includes extensions`() {
    val keyPair = genECKeyPair()
    val subject = X500Principal("CN=Test User,O=Test Org")
    val cert =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            issuer = subject,
            subject = subject,
            notBefore = LocalDate(2024, 1, 1),
            notAfter = LocalDate(2025, 12, 31),
            sans = listOf(San.Dns("example.com")),
        )

    assertEquals("Test User", cert.commonName)
    assertTrue(cert.isCA)
  }

  @Test
  fun `buildSelfSigned certificate is trusted in a trust store`() {
    val keyPair = genECKeyPair()
    val subject = X500Principal("CN=Trust Test")
    val cert =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            issuer = subject,
            subject = subject,
            notBefore = LocalDate(2024, 1, 1),
            notAfter = LocalDate(2025, 12, 31),
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
    val cert =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            issuer = subject,
            subject = subject,
            notBefore = LocalDate(2024, 1, 1),
            notAfter = LocalDate(2025, 12, 31),
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
