package certkit.cert

import certkit.pem.Pem
import certkit.pem.pem
import java.math.BigInteger
import java.net.InetAddress
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal
import kotlinx.datetime.LocalDate
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class CertTest {

  // -- buildSelfSigned --------------------------------------------------------------------------

  @Test
  fun `buildSelfSigned produces a valid self-signed CA certificate`() {
    val keyPair = generateECKeyPair()
    val subject = X500Principal("CN=Test,O=Test Org")
    val cert =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            serialNumber = 1,
            issuer = subject,
            subject = subject,
            notBefore = LocalDate(2024, 1, 1),
            notAfter = LocalDate(2025, 12, 31),
            sanDnsNames = listOf("localhost"),
            sanIpAddresses = listOf(InetAddress.getLoopbackAddress()),
        )

    assertTrue(cert.selfSigned)
    assertTrue(cert.isCA)
    assertFalse(cert.isIntermediateCA)
  }

  @Test
  fun `buildSelfSigned sets certificate fields correctly`() {
    val keyPair = generateECKeyPair()
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

  // -- certificate extensions -------------------------------------------------------------------

  @Test
  fun `buildSelfSigned includes extensions`() {
    val keyPair = generateECKeyPair()
    val subject = X500Principal("CN=Test User,O=Test Org")
    val cert =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            issuer = subject,
            subject = subject,
            notBefore = LocalDate(2024, 1, 1),
            notAfter = LocalDate(2025, 12, 31),
            sanDnsNames = listOf("example.com"),
        )

    assertEquals("Test User", cert.commonName)
    assertTrue(cert.isCA)
  }

  // -- trust store integration ------------------------------------------------------------------

  @Test
  fun `buildSelfSigned certificate is trusted in a trust store`() {
    val keyPair = generateECKeyPair()
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
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(keyStore)
    for (tm in tmf.trustManagers) {
      if (tm is X509TrustManager) {
        tm.checkServerTrusted(arrayOf(cert), "EC")
      }
    }
  }

  // -- PEM encoding -----------------------------------------------------------------------------

  @Test
  fun `certificate PEM round-trip`() {
    val keyPair = generateECKeyPair()
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
    val keyPair = generateECKeyPair()

    assertTrue(keyPair.public.pem.startsWith("-----BEGIN PUBLIC KEY-----"))
    assertTrue(keyPair.private.pem.startsWith("-----BEGIN PRIVATE KEY-----"))
  }

  // -- helpers -----------------------------------------------------------------------------------

  private fun generateECKeyPair(): KeyPair =
      KeyPairGenerator.getInstance("EC")
          .apply { initialize(ECGenParameterSpec("secp256r1")) }
          .generateKeyPair()
}
