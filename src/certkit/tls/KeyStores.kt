package certkit.tls

import java.nio.file.Path
import java.security.KeyStore
import java.security.Security
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Trust store utilities for discovering available KeyStore types and accessing JDK's default
 * cacerts trust managers. Switchable via `-Djavax.net.ssl.trustStoreType=xxx`.
 */
object TrustStore {

  /** Lists all available KeyStore types from registered security providers. */
  fun allTrustStores(): List<String> =
      Security.getProviders()
          .flatMap { it.entries }
          .map { it.key.toString() }
          .filter { it.startsWith("KeyStore.") && !it.endsWith("ImplementedIn") }
          .map { it.substringAfter("KeyStore.").trim() }
          .distinct()

  /** Default trust managers initialized from JDK's `cacerts` trust store. */
  val jdkCACerts: List<X509TrustManager> by lazy {
    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).run {
      init(null as KeyStore?)
      trustManagers.filterIsInstance<X509TrustManager>()
    }
  }

  /** Loads the system trust store for the given [type]. */
  fun systemTrustStore(type: TrustStoreType): KeyStore =
      when (type) {
        is TrustStoreType.Directory -> KeyStore.getInstance(type.name).apply { load { null } }
        else -> KeyStore.getInstance(type.name).apply { load(null, null) }
      }

  /** Creates an in-memory KeyStore of the given [type]. */
  fun newKeyStore(type: String = KeyStore.getDefaultType()): KeyStore =
      KeyStore.getInstance(type).apply { load(null, null) }
}

/** Platform-specific trust store types. */
sealed class TrustStoreType(val name: String) {
  data object WinUser : TrustStoreType("Windows-MY")

  data object WinSystem : TrustStoreType("Windows-ROOT")

  data object MacUser : TrustStoreType("KeychainStore")

  data object MacSystem : TrustStoreType("KeychainStore-ROOT")

  class Directory(val path: Path) : TrustStoreType("Directory")
}

/** JSSE system and security properties for TLS configuration. */
enum class TLSProp(val prop: String, val desc: String, val system: Boolean = true) {
  Debug("javax.net.debug", "Debugging SSL/TLS connections"),
  KeyStore("javax.net.ssl.keyStore", "Default keystore"),
  KeyStoreType("javax.net.ssl.keyStoreType", "Default keystore type"),
  KeyStorePassword("javax.net.ssl.keyStorePassword", "Default keystore password"),
  KeyStoreProvider("javax.net.ssl.keyStoreProvider", "Default keystore provider"),
  TrustStore("javax.net.ssl.trustStore", "Default truststore"),
  TrustStoreType("javax.net.ssl.trustStoreType", "Default truststore type"),
  TrustStorePassword("javax.net.ssl.trustStorePassword", "Default truststore password"),
  TrustStoreProvider("javax.net.ssl.trustStoreProvider", "Default truststore provider"),
  ProxyHost("https.proxyHost", "Default HTTPS proxy host"),
  ProxyPort("https.proxyPort", "Default HTTPS proxy port"),
  HttpsCipherSuites("https.cipherSuites", "Default cipher suites"),
  HttpsProtocols("https.protocols", "Default HTTPS handshaking protocols"),
  TLSProtocols("jdk.tls.client.protocols", "Default enabled TLS protocols"),
  CertPathDisabledAlgos(
      "jdk.certpath.disabledAlgorithms",
      "Disabled cert verification algorithms",
      false,
  ),
  TLSDisabledAlgos("jdk.tls.disabledAlgorithms", "Disabled/restricted algorithms", false);

  /** Sets this property value via system property or security property based on [system] flag. */
  fun set(value: String) {
    if (system) System.setProperty(prop, value) else Security.setProperty(prop, value)
  }
}
