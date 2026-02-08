package dev.suresh.certkit.cert

import dev.suresh.certkit.pem.pem
import java.net.InetAddress
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal
import kotlinx.datetime.LocalDate
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CertTest {

    @Test
    fun `build self-signed certificate`() {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val subject = X500Principal("CN=Test,O=Test Org")
        val certificate = Cert.buildSelfSigned(
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
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
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
    fun `certificate extensions`() {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val subject = X500Principal("CN=Test User,O=Test Org")
        val certificate = Cert.buildSelfSigned(
            keyPair = keyPair,
            serialNumber = 42,
            issuer = subject,
            subject = subject,
            notBefore = LocalDate(2024, 1, 1),
            notAfter = LocalDate(2025, 12, 31),
            sanDnsNames = listOf("example.com"),
        )

        assertTrue(certificate.selfSigned)
        assertTrue(certificate.commonName == "Test User")
        assertNotNull(certificate.pem)
        assertTrue(certificate.pem.contains("BEGIN CERTIFICATE"))
        assertNotNull(certificate.expiryDateUTC)
    }
}
