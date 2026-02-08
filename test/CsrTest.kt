package dev.suresh.certkit.csr

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.security.auth.x500.X500Principal
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CsrTest {

    @Test
    fun `signature algorithm identifiers are available`() {
        val algorithms = Csr.allSignatureAlgorithms()
        assertTrue(algorithms.isNotEmpty())
        assertNotNull(algorithms["SHA256withRSA"])
        assertNotNull(algorithms["SHA256withECDSA"])
    }

    @Test
    fun `create CSR with RSA key`() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val csr = Csr.create("CN=test", "SHA256withRSA", keyPair)
        assertNotNull(csr.encoded)
        assertTrue(csr.pemEncoded.contains("BEGIN CERTIFICATE REQUEST"))
        assertEquals("CN=test", csr.info.subject.name)
    }

    @Test
    fun `create CSR with EC key`() {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val csr = Csr.create("CN=ec-test", "SHA256withECDSA", keyPair)
        assertNotNull(csr.encoded)
        assertTrue(csr.pemEncoded.contains("BEGIN CERTIFICATE REQUEST"))
    }

    @Test
    fun `CSR equality`() {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val info = CertificationRequestInfo(X500Principal("CN=test"), keyPair.public)
        val algorithmId = Csr.findSignatureAlgorithm("SHA256withECDSA")
        val signature = info.sign(algorithmId, keyPair.private)

        val csr1 = Csr.create(info, algorithmId, signature)
        val csr2 = Csr.create(info, algorithmId, signature)
        assertEquals(csr1, csr2)
        assertEquals(csr1.hashCode(), csr2.hashCode())
    }

    @Test
    fun `CertificationRequestInfo equality`() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val subject = X500Principal("CN=test")
        val info1 = CertificationRequestInfo(subject, keyPair.public)
        val info2 = CertificationRequestInfo(subject, keyPair.public)
        assertEquals(info1, info2)
        assertEquals(info1.hashCode(), info2.hashCode())
    }
}
