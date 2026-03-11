package certkit.tls

import java.net.Socket
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Principal
import java.security.spec.ECGenParameterSpec
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.X509KeyManager

/** Generates an Ed25519 [KeyPair]. Requires JDK 15+. */
fun newEd25519KeyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

/** Generates an Elliptic Curve [KeyPair] using the given [curve] (default: P-256). */
fun newEcKeyPair(curve: String = "secp256r1"): KeyPair =
    KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()

/** Generates an RSA [KeyPair] with the given [keySize] (default: 3072). */
fun newRsaKeyPair(keySize: Int = 3072): KeyPair =
    KeyPairGenerator.getInstance("RSA").apply { initialize(keySize) }.generateKeyPair()

/** Creates an in-memory KeyStore of the given [type]. */
fun newKeyStore(type: String = KeyStore.getDefaultType()): KeyStore =
    KeyStore.getInstance(type).apply { load(null, null) }

/** Returns [X509KeyManager]s initialized from this [KeyStore] with the given [passwd]. */
fun KeyStore.keyManagers(passwd: CharArray? = null): List<X509KeyManager> =
    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).let { km ->
      km.init(this, passwd)
      km.keyManagers.filterIsInstance<X509KeyManager>()
    }

/**
 * Converts this keystore to PKCS12 format (the default since JDK 9), or returns it as-is if already
 * PKCS12.
 */
fun KeyStore.toPkcs12(keyPassword: CharArray? = null): KeyStore =
    if (type.equals("pkcs12", ignoreCase = true)) this
    else {
      val p12 = newKeyStore("pkcs12")
      aliases().toList().forEach { alias ->
        val protParam = if (isKeyEntry(alias)) KeyStore.PasswordProtection(keyPassword) else null
        p12.setEntry(alias, getEntry(alias, protParam), protParam)
      }
      p12
    }

/** Key manager that always selects a specific alias for client authentication. */
class AliasKeyManager(
    private val delegate: X509KeyManager,
    private val aliasName: String,
) : X509KeyManager by delegate {
  override fun chooseClientAlias(
      keyType: Array<String>,
      issuers: Array<Principal>,
      socket: Socket,
  ): String = aliasName
}
