package certkit.pem

import certkit.resBytes
import certkit.resText
import certkit.tls.newKeyStore
import kotlin.io.encoding.Base64
import kotlin.test.*
import kotlinx.io.Buffer
import kotlinx.io.asOutputStream
import kotlinx.io.readByteArray

class KeyStoreTest {

  private val storePass = "certkit"

  @Test
  fun `parseKeyStore extracts key cert and chain matching original files`() {
    listOf("rsa", "ec", "dsa").forEach { type ->
      val bundle = parseKeyStore(Base64.encode(resBytes("$type.client.p12")), storePass)

      val expectedKey = Pem.loadPrivateKey(resText("$type.client.pkcs8.key"))
      val expectedCert = Pem.readCertificateChain(resText("$type.client.crt")).single()
      val expectedCa = Pem.readCertificateChain(resText("$type.ca.crt")).single()

      assertEquals(
          expected = expectedKey,
          actual = Pem.loadPrivateKey(bundle.key),
          message = "$type key mismatch",
      )
      assertEquals(
          expected = expectedCert,
          actual = Pem.readCertificateChain(bundle.cert).single(),
          message = "$type cert mismatch",
      )
      assertEquals(
          expected = expectedCa,
          actual = Pem.readCertificateChain(bundle.certChain).single(),
          message = "$type CA mismatch",
      )
    }
  }

  @Test
  fun `parseKeyStore with keyPass produces decryptable key`() {
    val keyPass = "secret"
    val bundle =
        parseKeyStore(Base64.encode(resBytes("rsa.client.p12")), storePass, keyPass = keyPass)
    val expectedKey = Pem.loadPrivateKey(resText("rsa.client.pkcs8.key"))
    assertEquals(expectedKey, Pem.loadPrivateKey(bundle.key, keyPass))
    assertEquals(keyPass, bundle.keyPass)
  }

  @Test
  fun `parseKeyStore with pkcs1 produces correct RSA key`() {
    val bundle = parseKeyStore(Base64.encode(resBytes("rsa.client.p12")), storePass, pkcs1 = true)
    val expectedKey = Pem.loadPrivateKey(resText("rsa.client.pkcs1.key"))
    assertEquals(expectedKey, Pem.loadPrivateKey(bundle.key))
  }

  @Test
  fun `parseKeyStore fails for empty keystore`() {
    val emptyP12 =
        Buffer()
            .also { buf -> newKeyStore().store(buf.asOutputStream(), "pass".toCharArray()) }
            .readByteArray()
    assertFailsWith<IllegalStateException> { parseKeyStore(Base64.encode(emptyP12), "pass") }
  }
}
