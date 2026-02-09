package certkit.cert

import certkit.pem.pem
import java.math.BigInteger
import java.net.InetAddress
import java.security.*
import java.security.spec.*
import javax.net.ssl.*
import javax.security.auth.x500.X500Principal
import kotlinx.datetime.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class CertTest {

  @Test
  fun `build self-signed certificate`() {
    val keyPair = generateECKeyPair()
    val subject = X500Principal("CN=Test,O=Test Org")
    val certificate =
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

    assertNotNull(certificate)
    assertTrue(certificate.selfSigned)
    assertTrue(certificate.isCA)

    // Verify the certificate is trusted when added to a trust store
    val keyStore =
        KeyStore.getInstance(KeyStore.getDefaultType()).apply {
          load(null, null)
          setCertificateEntry("test", certificate)
        }
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(keyStore)
    for (tm in tmf.trustManagers) {
      if (tm is X509TrustManager) {
        tm.checkServerTrusted(arrayOf(certificate), "EC")
      }
    }
  }

  @Test
  fun `certificate fields are correct`() {
    val keyPair = generateECKeyPair()
    val issuer = X500Principal("CN=issuer,O=Airlift")
    val subject = X500Principal("CN=subject,O=Airlift")
    val certificate =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            serialNumber = 12345,
            issuer = issuer,
            subject = subject,
            notBefore = LocalDate(2024, 1, 1),
            notAfter = LocalDate(2025, 12, 31),
        )

    assertEquals(BigInteger.valueOf(12345), certificate.serialNumber)
    assertEquals(issuer, certificate.issuerX500Principal)
    assertEquals(subject, certificate.subjectX500Principal)
    assertEquals(keyPair.public, certificate.publicKey)

    // Verify notBefore = 2024-01-01T00:00:00Z
    val notBeforeInstant = certificate.notBefore.toInstant()
    assertEquals("2024-01-01T00:00:00Z", notBeforeInstant.toString())

    // Verify notAfter = 2025-12-31T23:59:59Z
    val notAfterInstant = certificate.notAfter.toInstant()
    assertEquals("2025-12-31T23:59:59Z", notAfterInstant.toString())
  }

  @Test
  fun `certificate extensions`() {
    val keyPair = generateECKeyPair()
    val subject = X500Principal("CN=Test User,O=Test Org")
    val certificate =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            serialNumber = 42,
            issuer = subject,
            subject = subject,
            notBefore = LocalDate(2024, 1, 1),
            notAfter = LocalDate(2025, 12, 31),
            sanDnsNames = listOf("example.com"),
        )

    assertTrue(certificate.selfSigned)
    assertEquals("Test User", certificate.commonName)
    assertNotNull(certificate.pem)
    assertTrue(certificate.pem.contains("BEGIN CERTIFICATE"))
    assertNotNull(certificate.expiryDateUTC)
    assertTrue(certificate.isCA)
    assertFalse(certificate.isIntermediateCA) // self-signed CA is not intermediate
  }

  @Test
  fun `PEM round-trip`() {
    val keyPair = generateECKeyPair()
    val subject = X500Principal("CN=RoundTrip")
    val certificate =
        Cert.buildSelfSigned(
            keyPair = keyPair,
            issuer = subject,
            subject = subject,
            notBefore = LocalDate(2024, 1, 1),
            notAfter = LocalDate(2025, 12, 31),
        )

    val pemString = certificate.pem
    assertTrue(pemString.startsWith("-----BEGIN CERTIFICATE-----"))
    assertTrue(pemString.trimEnd().endsWith("-----END CERTIFICATE-----"))

    val publicKeyPem = keyPair.public.pem
    assertTrue(publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----"))

    val privateKeyPem = keyPair.private.pem
    assertTrue(privateKeyPem.startsWith("-----BEGIN PRIVATE KEY-----"))
  }

  private fun generateECKeyPair(): KeyPair =
      KeyPairGenerator.getInstance("EC")
          .apply { initialize(ECGenParameterSpec("secp256r1")) }
          .generateKeyPair()
}
