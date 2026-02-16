package certkit.csr

import certkit.pem.pem
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.security.auth.x500.X500Principal
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class CsrTest {

  // -- Csr.signatureAlgorithms -------------------------------------------------------------------

  @Test
  fun `signatureAlgorithms discovers RSA and EC from JCA providers`() {
    assertTrue(Csr.signatureAlgorithms.isNotEmpty())
    assertNotNull(Csr.signatureAlgorithms["SHA256withRSA"])
    assertNotNull(Csr.signatureAlgorithms["SHA256withECDSA"])
  }

  // -- Csr.create --------------------------------------------------------------------------------

  @Test
  fun `create with RSA key produces verifiable CSR`() {
    val keyPair = generateRSAKeyPair()
    val csr = Csr.create("CN=test", "SHA256withRSA", keyPair)

    assertEquals("CN=test", csr.info.subject.name)
    assertTrue(csr.pem.contains("BEGIN CERTIFICATE REQUEST"))
    verifySignature(csr, keyPair)
  }

  @Test
  fun `create with EC key produces verifiable CSR`() {
    val keyPair = generateECKeyPair()
    val csr = Csr.create("CN=test", "SHA256withECDSA", keyPair)

    assertEquals("CN=test", csr.info.subject.name)
    verifySignature(csr, keyPair)
  }

  @Test
  fun `create with unknown algorithm throws`() {
    assertThrows<IllegalStateException> {
      val _ = Csr.create("CN=test", "NoSuchAlgorithm", generateRSAKeyPair())
    }
  }

  // -- Csr.create with SANs ---------------------------------------------------------------------

  @Test
  fun `create with DNS SANs`() {
    val keyPair = generateECKeyPair()
    val sans = listOf(San.Dns("example.com"), San.Dns("*.example.com"))
    val csr = Csr.create("CN=example.com", "SHA256withECDSA", keyPair, sans)

    assertEquals(sans, csr.info.sans)
    verifySignature(csr, keyPair)
  }

  @Test
  fun `create with mixed SANs`() {
    val keyPair = generateRSAKeyPair()
    val sans = listOf(San.Dns("example.com"), San.Ip("10.0.0.1"), San.Email("admin@example.com"))
    val csr = Csr.create("CN=example.com", "SHA256withRSA", keyPair, sans)

    assertEquals(sans, csr.info.sans)
    verifySignature(csr, keyPair)
  }

  @Test
  fun `create with IPv6 SAN`() {
    val keyPair = generateECKeyPair()
    val csr = Csr.create("CN=test", "SHA256withECDSA", keyPair, listOf(San.Ip("::1")))

    assertEquals(listOf(San.Ip("::1")), csr.info.sans)
    verifySignature(csr, keyPair)
  }

  // -- CsrInfo ----------------------------------------------------------------------------------

  @Test
  fun `CsrInfo equality and hashCode`() {
    val keyPair = generateRSAKeyPair()
    val subject = X500Principal("CN=test")
    val info1 = CsrInfo(subject, keyPair.public)
    val info2 = CsrInfo(subject, keyPair.public)

    assertEquals(info1, info2)
    assertEquals(info1.hashCode(), info2.hashCode())
  }

  // -- SignatureAlgo -----------------------------------------------------------------------------

  @Test
  fun `SignatureAlgo equality is by OID`() {
    val alg1 = SignatureAlgo("SHA256withRSA", "1.2.840.113549.1.1.11")
    val alg2 = SignatureAlgo("SHA256withRSA", "1.2.840.113549.1.1.11")
    val alg3 = SignatureAlgo("SHA256withECDSA", "1.2.840.10045.4.3.2")

    assertEquals(alg1, alg2)
    assertEquals(alg1.hashCode(), alg2.hashCode())
    assertNotEquals(alg1, alg3)
  }

  // -- helpers -----------------------------------------------------------------------------------

  private fun verifySignature(csr: CsrRequest, keyPair: KeyPair) {
    val verifier = Signature.getInstance(csr.algorithm.name)
    verifier.initVerify(keyPair.public)
    verifier.update(csr.info.encoded)
    assertTrue(verifier.verify(csr.signature))
  }

  private fun generateECKeyPair(): KeyPair =
      KeyPairGenerator.getInstance("EC")
          .apply { initialize(ECGenParameterSpec("secp256r1")) }
          .generateKeyPair()

  private fun generateRSAKeyPair(): KeyPair =
      KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
}
