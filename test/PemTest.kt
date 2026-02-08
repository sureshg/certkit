package dev.suresh.certkit.pem

import java.nio.file.Path
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.naming.ldap.LdapName
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PemTest {

    @Test
    fun `load key store - PKCS8 unencrypted`() {
        testLoadKeyStore("rsa.client.crt", "rsa.client.pkcs8.key", null, CLIENT_NAME)
        testLoadKeyStore("ec.client.crt", "ec.client.pkcs8.key", null, CLIENT_NAME)
        testLoadKeyStore("dsa.client.crt", "dsa.client.pkcs8.key", null, CLIENT_NAME)
    }

    @Test
    fun `load key store - PKCS8 encrypted`() {
        testLoadKeyStore("rsa.client.crt", "rsa.client.pkcs8.key.encrypted", KEY_PASSWORD, CLIENT_NAME)
        testLoadKeyStore("ec.client.crt", "ec.client.pkcs8.key.encrypted", KEY_PASSWORD, CLIENT_NAME)
        testLoadKeyStore("dsa.client.crt", "dsa.client.pkcs8.key.encrypted", KEY_PASSWORD, CLIENT_NAME)
    }

    @Test
    fun `load key store - PEM encrypted`() {
        testLoadKeyStore("rsa.client.pkcs8.pem.encrypted", "rsa.client.pkcs8.pem.encrypted", KEY_PASSWORD, CLIENT_NAME)
        testLoadKeyStore("dsa.client.pkcs8.pem.encrypted", "dsa.client.pkcs8.pem.encrypted", KEY_PASSWORD, CLIENT_NAME)
        testLoadKeyStore("ec.client.pkcs8.pem.encrypted", "ec.client.pkcs8.pem.encrypted", KEY_PASSWORD, CLIENT_NAME)
    }

    @Test
    fun `load key store - PKCS1 unencrypted`() {
        testLoadKeyStore("rsa.client.crt", "rsa.client.pkcs1.key", null, CLIENT_NAME)
        testLoadKeyStore("ec.client.crt", "ec.client.pkcs1.key", null, CLIENT_NAME)
        testLoadKeyStore("dsa.client.crt", "dsa.client.pkcs1.key", null, CLIENT_NAME)
    }

    @Test
    fun `load key store - PKCS1 PEM`() {
        testLoadKeyStore("rsa.client.pkcs8.pem.encrypted", "rsa.client.pkcs1.pem", null, CLIENT_NAME)
        testLoadKeyStore("dsa.client.pkcs8.pem.encrypted", "dsa.client.pkcs1.pem", null, CLIENT_NAME)
        testLoadKeyStore("ec.client.pkcs8.pem.encrypted", "ec.client.pkcs1.pem", null, CLIENT_NAME)
    }

    @Test
    fun `load trust store`() {
        assertCertificateChain(Pem.loadTrustStore(resourcePath("rsa.ca.crt")), CA_NAME)
        assertCertificateChain(Pem.loadTrustStore(resourcePath("ec.ca.crt")), CA_NAME)
        assertCertificateChain(Pem.loadTrustStore(resourcePath("dsa.ca.crt")), CA_NAME)
    }

    @Test
    fun `load public key`() {
        testLoadPublicKey("rsa.client.crt", "rsa.client.pkcs8.pub")
        testLoadPublicKey("rsa.client.crt", "rsa.client.pkcs1.pub")
        testLoadPublicKey("ec.client.crt", "ec.client.pkcs8.pub")
        testLoadPublicKey("dsa.client.crt", "dsa.client.pkcs8.pub")
    }

    @Test
    fun `PKCS1 and PKCS8 private keys produce same key`() {
        // RSA
        val rsaPkcs8 = Pem.loadPrivateKey(resourcePath("rsa.client.pkcs8.key"))
        val rsaPkcs1 = Pem.loadPrivateKey(resourcePath("rsa.client.pkcs1.key"))
        assertEquals(rsaPkcs8, rsaPkcs1)

        // DSA
        val dsaPkcs8 = Pem.loadPrivateKey(resourcePath("dsa.client.pkcs8.key"))
        val dsaPkcs1 = Pem.loadPrivateKey(resourcePath("dsa.client.pkcs1.key"))
        assertEquals(dsaPkcs8, dsaPkcs1)

        // EC
        val ecPkcs8 = Pem.loadPrivateKey(resourcePath("ec.client.pkcs8.key"))
        val ecPkcs1 = Pem.loadPrivateKey(resourcePath("ec.client.pkcs1.key"))
        assertEquals(ecPkcs8, ecPkcs1)
    }

    @Test
    fun `RSA public key PKCS1 and PKCS8 produce same key`() {
        val pkcs8Key = Pem.loadPublicKey(resourcePath("rsa.client.pkcs8.pub"))
        val pkcs1Key = Pem.loadPublicKey(resourcePath("rsa.client.pkcs1.pub"))
        assertEquals(pkcs8Key, pkcs1Key)
    }

    // --- Helpers ---

    private fun testLoadKeyStore(certFile: String, keyFile: String, keyPassword: String?, expectedName: String) {
        val keyStore = Pem.loadKeyStore(resourcePath(certFile), resourcePath(keyFile), keyPassword)
        assertCertificateChain(keyStore, expectedName)
        assertNotNull(keyStore.getCertificate("key"))

        val key = keyStore.getKey("key", charArrayOf()) as PrivateKey
        assertNotNull(key)
        assertEquals(key, Pem.loadPrivateKey(key.pem))
    }

    private fun testLoadPublicKey(certFile: String, keyFile: String) {
        val path = resourcePath(keyFile)
        assertTrue(Pem.isPem(path))
        val publicKey = Pem.loadPublicKey(path)
        assertNotNull(publicKey)
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

    private fun resourcePath(name: String): Path {
        val url = this::class.java.classLoader.getResource(name)
            ?: throw IllegalArgumentException("Resource not found: $name")
        return Path.of(url.toURI())
    }
}

private const val CA_NAME = "OU=RootCA,O=Airlift,L=Palo Alto,ST=CA,C=US"
private const val CLIENT_NAME = "CN=Test User,OU=Server,O=Airlift,L=Palo Alto,ST=CA,C=US"
private const val KEY_PASSWORD = "airlift"
