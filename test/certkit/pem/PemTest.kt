package certkit.pem

import kotlin.io.path.toPath
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.naming.ldap.LdapName
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class PemTest {

  companion object {
    private const val CA_NAME = "OU=RootCA,O=Airlift,L=Palo Alto,ST=CA,C=US"
    private const val CLIENT_NAME = "CN=Test User,OU=Server,O=Airlift,L=Palo Alto,ST=CA,C=US"
    private const val KEY_PASSWORD = "airlift"
  }

  @Test
  fun `isPem detects certificates, keys, and rejects non-PEM`() {
    assertTrue(Pem.isPem(resourcePath("rsa.client.crt")))
    assertTrue(Pem.isPem(resourcePath("rsa.client.pkcs8.key")))
    assertTrue(Pem.isPem(resourcePath("rsa.client.pkcs8.pub")))
    assertFalse(Pem.isPem("not a pem string"))
  }

  @Test
  fun `loadTrustStore loads RSA, EC, and DSA CA certificates`() {
    assertCertificateChain(Pem.loadTrustStore(resourcePath("rsa.ca.crt")), CA_NAME)
    assertCertificateChain(Pem.loadTrustStore(resourcePath("ec.ca.crt")), CA_NAME)
    assertCertificateChain(Pem.loadTrustStore(resourcePath("dsa.ca.crt")), CA_NAME)
  }

  @Test
  fun `loadKeyStore with PKCS8 unencrypted keys`() {
    testLoadKeyStore("rsa.client.crt", "rsa.client.pkcs8.key", null, CLIENT_NAME)
    testLoadKeyStore("ec.client.crt", "ec.client.pkcs8.key", null, CLIENT_NAME)
    testLoadKeyStore("dsa.client.crt", "dsa.client.pkcs8.key", null, CLIENT_NAME)
  }

  @Test
  fun `loadKeyStore with PKCS8 encrypted keys`() {
    testLoadKeyStore("rsa.client.crt", "rsa.client.pkcs8.key.encrypted", KEY_PASSWORD, CLIENT_NAME)
    testLoadKeyStore("ec.client.crt", "ec.client.pkcs8.key.encrypted", KEY_PASSWORD, CLIENT_NAME)
    testLoadKeyStore("dsa.client.crt", "dsa.client.pkcs8.key.encrypted", KEY_PASSWORD, CLIENT_NAME)
  }

  @Test
  fun `loadKeyStore with PKCS8 PEM encrypted`() {
    testLoadKeyStore(
        "rsa.client.pkcs8.pem.encrypted",
        "rsa.client.pkcs8.pem.encrypted",
        KEY_PASSWORD,
        CLIENT_NAME,
    )
    testLoadKeyStore(
        "dsa.client.pkcs8.pem.encrypted",
        "dsa.client.pkcs8.pem.encrypted",
        KEY_PASSWORD,
        CLIENT_NAME,
    )
    testLoadKeyStore(
        "ec.client.pkcs8.pem.encrypted",
        "ec.client.pkcs8.pem.encrypted",
        KEY_PASSWORD,
        CLIENT_NAME,
    )
  }

  @Test
  fun `loadKeyStore with PKCS1 unencrypted keys`() {
    testLoadKeyStore("rsa.client.crt", "rsa.client.pkcs1.key", null, CLIENT_NAME)
    testLoadKeyStore("ec.client.crt", "ec.client.pkcs1.key", null, CLIENT_NAME)
    testLoadKeyStore("dsa.client.crt", "dsa.client.pkcs1.key", null, CLIENT_NAME)
  }

  @Test
  fun `loadKeyStore with PKCS1 PEM keys`() {
    testLoadKeyStore("rsa.client.pkcs8.pem.encrypted", "rsa.client.pkcs1.pem", null, CLIENT_NAME)
    testLoadKeyStore("dsa.client.pkcs8.pem.encrypted", "dsa.client.pkcs1.pem", null, CLIENT_NAME)
    testLoadKeyStore("ec.client.pkcs8.pem.encrypted", "ec.client.pkcs1.pem", null, CLIENT_NAME)
  }

  @Test
  fun `loadPrivateKey PKCS1 and PKCS8 produce same key`() {
    assertEquals(
        Pem.loadPrivateKey(resourcePath("rsa.client.pkcs8.key")),
        Pem.loadPrivateKey(resourcePath("rsa.client.pkcs1.key")),
    )
    assertEquals(
        Pem.loadPrivateKey(resourcePath("dsa.client.pkcs8.key")),
        Pem.loadPrivateKey(resourcePath("dsa.client.pkcs1.key")),
    )
    assertEquals(
        Pem.loadPrivateKey(resourcePath("ec.client.pkcs8.key")),
        Pem.loadPrivateKey(resourcePath("ec.client.pkcs1.key")),
    )
  }

  @Test
  fun `loadPrivateKey throws on missing key`() {
    assertThrows<IllegalStateException> { val _ = Pem.loadPrivateKey("no key here") }
  }

  @Test
  fun `loadPrivateKey throws on encrypted key without password`() {
    assertThrows<IllegalStateException> {
      val _ = Pem.loadPrivateKey(resourcePath("rsa.client.pkcs8.key.encrypted"), null)
    }
  }

  @Test
  fun `loadPublicKey matches certificate public key`() {
    testLoadPublicKey("rsa.client.crt", "rsa.client.pkcs8.pub")
    testLoadPublicKey("ec.client.crt", "ec.client.pkcs8.pub")
    testLoadPublicKey("dsa.client.crt", "dsa.client.pkcs8.pub")
  }

  @Test
  fun `loadPublicKey RSA PKCS1 and PKCS8 produce same key`() {
    assertEquals(
        Pem.loadPublicKey(resourcePath("rsa.client.pkcs8.pub")),
        Pem.loadPublicKey(resourcePath("rsa.client.pkcs1.pub")),
    )
  }

  @Test
  fun `loadPublicKey throws on missing key`() {
    assertThrows<IllegalStateException> { val _ = Pem.loadPublicKey("no key here") }
  }

  private fun testLoadKeyStore(
      certFile: String,
      keyFile: String,
      keyPassword: String?,
      expectedName: String,
  ) {
    val keyStore = Pem.loadKeyStore(resourcePath(certFile), resourcePath(keyFile), keyPassword)
    assertCertificateChain(keyStore, expectedName)
    val key = keyStore.getKey("key", charArrayOf()) as PrivateKey
    assertEquals(key, Pem.loadPrivateKey(key.pem))
  }

  private fun testLoadPublicKey(certFile: String, keyFile: String) {
    val publicKey = Pem.loadPublicKey(resourcePath(keyFile))
    assertEquals(publicKey, Pem.readCertificateChain(resourcePath(certFile)).single().publicKey)
    assertEquals(publicKey, Pem.loadPublicKey(publicKey.pem))
  }

  private fun assertCertificateChain(keyStore: KeyStore, expectedName: String) {
    val aliases = keyStore.aliases().toList()
    assertEquals(1, aliases.size)
    val cert = keyStore.getCertificate(aliases.first()) as X509Certificate
    assertX509Certificate(cert, expectedName)
    assertX509Certificate(Pem.readCertificateChain(cert.pem).single(), expectedName)
  }

  private fun assertX509Certificate(cert: X509Certificate, expectedName: String) {
    assertEquals(expectedName, LdapName(cert.subjectX500Principal.name).toString())
  }

  private fun resourcePath(name: String) =
      this::class.java.classLoader.getResource(name)?.toURI()?.toPath() ?: error("Resource not found: $name")
}
