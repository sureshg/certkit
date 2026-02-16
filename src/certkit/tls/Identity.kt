package certkit.tls

import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.X509KeyManager

/** Creates an in-memory KeyStore of the given [type]. */
fun newKeyStore(type: String = KeyStore.getDefaultType()): KeyStore =
    KeyStore.getInstance(type).apply { load(null, null) }

/** Returns [X509KeyManager]s initialized from this [KeyStore] with the given [passwd]. */
fun KeyStore.keyManagers(passwd: CharArray? = null): List<X509KeyManager> =
    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).let { km ->
      km.init(this, passwd)
      km.keyManagers.filterIsInstance<X509KeyManager>()
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
