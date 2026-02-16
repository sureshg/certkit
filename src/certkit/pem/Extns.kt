package certkit.pem

import certkit.csr.CsrRequest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import kotlin.io.encoding.Base64

/** Encodes a byte array as a PEM block with the given [type] header/footer. */
fun ByteArray.encodePem(type: PemType): String = buildString {
  appendLine("-----BEGIN ${type.marker}-----")
  appendLine(Base64.encode(this@encodePem).chunked(64).joinToString("\n"))
  appendLine("-----END ${type.marker}-----")
}

/** PEM-encoded representation of this public key. */
val PublicKey.pem: String
  get() = encoded.encodePem(PemType.PUBLIC)

/** PEM-encoded representation of this private key (PKCS#8). */
val PrivateKey.pem: String
  get() = encoded.encodePem(PemType.PKCS8INF)

/** PEM-encoded representation of this X.509 certificate. */
val X509Certificate.pem: String
  get() = encoded.encodePem(PemType.X509)

/** PEM-encoded representation of this PKCS#10 certification request. */
val CsrRequest.pem: String
  get() = encoded.encodePem(PemType.X509_REQ)
