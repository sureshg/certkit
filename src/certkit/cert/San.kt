package certkit.cert

import certkit.der.Der
import java.net.InetAddress

/** Subject Alternative Name entry for X.509 certificates and CSR extension requests. */
sealed interface San {
  data class Dns(val name: String) : San

  data class Ip(val address: String) : San

  data class Email(val address: String) : San

  /** DER-encodes this SAN as a context-tagged GeneralName (RFC 5280 §4.2.1.6). */
  fun toDer(): ByteArray =
      when (this) {
        is Dns -> Der.contextTag(2, name.encodeToByteArray())
        is Email -> Der.contextTag(1, address.encodeToByteArray())
        is Ip -> Der.contextTag(7, InetAddress.getByName(address).address)
      }
}
