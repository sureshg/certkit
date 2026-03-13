package certkit.cert

import certkit.der.Der
import java.net.InetAddress

/** Subject Alternative Name entry for X.509 certificates and CSR extension requests. */
public sealed interface San {
  public data class Dns(val name: String) : San

  public data class Ip(val address: String) : San

  public data class Email(val address: String) : San

  /** DER-encodes this SAN as a context-tagged GeneralName (RFC 5280 §4.2.1.6). */
  public fun toDer(): ByteArray =
      when (this) {
        is Dns -> Der.implicitTag(2, name.encodeToByteArray())
        is Email -> Der.implicitTag(1, address.encodeToByteArray())
        is Ip -> Der.implicitTag(7, InetAddress.getByName(address).address)
      }
}
