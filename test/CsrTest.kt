package dev.suresh.certkit.csr

import java.security.*
import java.security.spec.*
import javax.security.auth.x500.X500Principal
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class CsrTest {

  @Test
  fun `signature algorithm identifiers are available`() {
    val algorithms = Csr.allSignatureAlgorithms()
    assertTrue(algorithms.isNotEmpty())
    assertNotNull(algorithms["SHA256withRSA"])
    assertNotNull(algorithms["SHA256withECDSA"])
  }

  @Test
  fun `find unknown algorithm throws`() {
    assertThrows<IllegalArgumentException> { Csr.findSignatureAlgorithm("NoSuchAlgorithm") }
  }

  @Test
  fun `create CSR with RSA key`() {
    val keyPair = generateRSAKeyPair()
    val csr = Csr.create("CN=test", "SHA256withRSA", keyPair)
    assertNotNull(csr.encoded)
    assertTrue(csr.pemEncoded.contains("BEGIN CERTIFICATE REQUEST"))
    assertEquals("CN=test", csr.info.subject.name)
  }

  @Test
  fun `create CSR with EC key`() {
    val keyPair = generateECKeyPair()
    val csr = Csr.create("CN=ec-test", "SHA256withECDSA", keyPair)
    assertNotNull(csr.encoded)
    assertTrue(csr.pemEncoded.contains("BEGIN CERTIFICATE REQUEST"))
  }

  @Test
  fun `CSR signature is verifiable`() {
    val keyPair = generateECKeyPair()
    val info = CertificationRequestInfo(X500Principal("C=country"), keyPair.public)
    val algorithmId = Csr.findSignatureAlgorithm("SHA256withECDSA")
    val sig = info.sign(algorithmId, keyPair.private)

    // Verify the signature is valid using raw JCA
    val verifier = Signature.getInstance(algorithmId.name)
    verifier.initVerify(keyPair.public)
    verifier.update(info.encoded)
    assertTrue(verifier.verify(sig))
  }

  @Test
  fun `CertificationRequestInfo encoding is stable`() {
    val keyPair = generateECKeyPair()
    val subject = X500Principal("C=country")
    val info1 = CertificationRequestInfo(subject, keyPair.public)
    val info2 = CertificationRequestInfo(subject, keyPair.public)
    assertArrayEquals(info1.encoded, info2.encoded)
  }

  @Test
  fun `CSR equality`() {
    val keyPair = generateECKeyPair()
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
    val keyPair = generateRSAKeyPair()
    val subject = X500Principal("CN=test")
    val info1 = CertificationRequestInfo(subject, keyPair.public)
    val info2 = CertificationRequestInfo(subject, keyPair.public)
    assertEquals(info1, info2)
    assertEquals(info1.hashCode(), info2.hashCode())
  }

  @Test
  fun `SignatureAlgorithmId equality by OID`() {
    val alg1 = SignatureAlgorithmId("SHA256withRSA", "1.2.840.113549.1.1.11")
    val alg2 = SignatureAlgorithmId("SHA256withRSA", "1.2.840.113549.1.1.11")
    val alg3 = SignatureAlgorithmId("SHA256withECDSA", "1.2.840.10045.4.3.2")
    assertEquals(alg1, alg2)
    assertEquals(alg1.hashCode(), alg2.hashCode())
    assertNotEquals(alg1, alg3)
  }

  private fun generateECKeyPair(): KeyPair =
      KeyPairGenerator.getInstance("EC")
          .apply { initialize(ECGenParameterSpec("secp256r1")) }
          .generateKeyPair()

  private fun generateRSAKeyPair(): KeyPair =
      KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
}
