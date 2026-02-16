package certkit.tls

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.Security
import java.security.cert.X509Certificate
import javax.net.ssl.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** Connects to a TLS server and captures the certificate chain presented during the handshake. */
fun scanCertificates(
    host: String,
    port: Int = 443,
    sni: String? = null,
    timeout: Duration = 5.seconds,
): List<X509Certificate> {
  val trustManager = CaptureTrustManager()
  val sslContext = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager), null) }
  val socket = sslContext.socketFactory.createSocket() as SSLSocket
  return socket.use { sock ->
    if (!sni.isNullOrBlank()) {
      sock.sslParameters = sock.sslParameters.apply { serverNames = listOf(SNIHostName(sni)) }
    }
    sock.soTimeout = timeout.inWholeMilliseconds.toInt()
    val _ = runCatching {
      sock.connect(InetSocketAddress(host, port), timeout.inWholeMilliseconds.toInt())
      sock.startHandshake()
    }
    trustManager.certChain
  }
}

/** SSLSocketFactory wrapper that disables SNI and hostname verification on created sockets. */
class ScanSSLFactory(private val delegate: SSLSocketFactory) : SSLSocketFactory() {
  override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites

  override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

  override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket =
      delegate.createSocket(s, host, port, autoClose).also { it.reconfigure() }

  override fun createSocket(host: String, port: Int): Socket =
      delegate.createSocket(host, port).also { it.reconfigure() }

  override fun createSocket(
      host: String,
      port: Int,
      localHost: InetAddress,
      localPort: Int,
  ): Socket = delegate.createSocket(host, port, localHost, localPort).also { it.reconfigure() }

  override fun createSocket(host: InetAddress, port: Int): Socket =
      delegate.createSocket(host, port).also { it.reconfigure() }

  override fun createSocket(
      address: InetAddress,
      port: Int,
      localAddress: InetAddress,
      localPort: Int,
  ): Socket =
      delegate.createSocket(address, port, localAddress, localPort).also { it.reconfigure() }

  private fun Socket.reconfigure() {
    val sslSock = this as SSLSocket
    sslSock.sslParameters =
        sslSock.sslParameters.apply {
          serverNames = emptyList()
          endpointIdentificationAlgorithm = null
        }
  }
}

/** JSSE system and security properties for TLS configuration. */
enum class TLSProp(val key: String, val desc: String, val system: Boolean = true) {
  // KeyStore
  KeyStore("javax.net.ssl.keyStore", "Default keystore"),
  KeyStoreType("javax.net.ssl.keyStoreType", "Default keystore type"),
  KeyStorePassword("javax.net.ssl.keyStorePassword", "Default keystore password"),
  KeyStoreProvider("javax.net.ssl.keyStoreProvider", "Default keystore provider"),

  // TrustStore
  TrustStore("javax.net.ssl.trustStore", "Default truststore"),
  TrustStoreType("javax.net.ssl.trustStoreType", "Default truststore type"),
  TrustStorePassword("javax.net.ssl.trustStorePassword", "Default truststore password"),
  TrustStoreProvider("javax.net.ssl.trustStoreProvider", "Default truststore provider"),

  // Protocols & Ciphers
  HttpsProtocols("https.protocols", "Default HTTPS handshaking protocols"),
  HttpsCipherSuites("https.cipherSuites", "Default cipher suites"),
  TLSProtocols("jdk.tls.client.protocols", "Default enabled TLS protocols"),

  // Security Restrictions (non-system)
  CertPathDisabledAlgos(
      "jdk.certpath.disabledAlgorithms",
      "Disabled cert verification algorithms",
      false,
  ),
  TLSDisabledAlgos("jdk.tls.disabledAlgorithms", "Disabled/restricted algorithms", false),

  // Proxy
  ProxyHost("https.proxyHost", "Default HTTPS proxy host"),
  ProxyPort("https.proxyPort", "Default HTTPS proxy port"),

  // Debug
  Debug("javax.net.debug", "Debugging SSL/TLS connections");

  fun set(value: String) {
    if (system) System.setProperty(key, value) else Security.setProperty(key, value)
  }
}
