package certkit.tls

import java.nio.file.Path
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** Platform-specific trust store types. */
public sealed class TrustStoreType(public val name: String) {
  public data object WinUser : TrustStoreType("Windows-MY")

  public data object WinSystem : TrustStoreType("Windows-ROOT")

  public data object MacUser : TrustStoreType("KeychainStore")

  public data object MacSystem : TrustStoreType("KeychainStore-ROOT")

  public class Directory(public val path: Path) : TrustStoreType("Directory")
}

/** Trust manager that captures the certificate chain presented during TLS handshake. */
public class CaptureTrustManager : X509TrustManager {
  public val certChain: List<X509Certificate>
    field = mutableListOf<X509Certificate>()

  override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

  override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
    certChain.addAll(chain)
  }

  override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
    certChain.addAll(chain)
  }
}

/** Lists all available KeyStore types from registered security providers. */
public fun allTrustStores(): List<String> =
    Security.getProviders()
        .flatMap { it.entries }
        .map { it.key.toString() }
        .filter { it.startsWith("KeyStore.") && !it.endsWith("ImplementedIn") }
        .map { it.substringAfter("KeyStore.").trim() }
        .distinct()

/** Default trust managers initialized from JDK's `cacerts` trust store. */
public val jdkCACerts: List<X509TrustManager> by lazy {
  TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).run {
    init(null as KeyStore?)
    trustManagers.filterIsInstance<X509TrustManager>()
  }
}

/** Loads the system trust store for the given [type]. */
public fun systemTrustStore(type: TrustStoreType): KeyStore =
    when (type) {
      is TrustStoreType.Directory -> KeyStore.getInstance(type.name).apply { load { null } }
      else -> newKeyStore(type.name)
    }

/** Returns [X509TrustManager]s initialized from this [KeyStore]. */
public val KeyStore.trustManagers: List<X509TrustManager>
  get() =
      TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).let { tm ->
        tm.init(this)
        tm.trustManagers.filterIsInstance<X509TrustManager>()
      }
