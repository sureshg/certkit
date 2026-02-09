package certkit.tls

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.Principal
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

/** Trust manager that captures the certificate chain presented during TLS handshake. */
class CaptureTrustManager : X509TrustManager {
  val certChain: List<X509Certificate>
    field = mutableListOf<X509Certificate>()

  override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
    certChain.addAll(chain)
  }

  override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
    certChain.addAll(chain)
  }

  override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
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
