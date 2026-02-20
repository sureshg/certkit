package certkit.csr

import certkit.cert.San
import java.security.KeyPair
import java.security.PrivateKey
import java.security.Security
import java.security.Signature
import javax.security.auth.x500.X500Principal

/**
 * PKCS#10 Certificate Signing Request factory, per
 * [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986).
 *
 * ```
 * CertificationRequest ::= SEQUENCE {
 *   certificationRequestInfo  CertificationRequestInfo,
 *   signatureAlgorithm        AlgorithmIdentifier,
 *   signature                 BIT STRING
 * }
 * ```
 */
object Csr {

  private const val SIGNATURE_OID_PREFIX = "Alg.Alias.Signature.OID."

  /** All signature algorithms discovered from JCA security providers, keyed by name. */
  val signatureAlgorithms: Map<String, SignatureAlgo> by lazy {
    buildMap {
      Security.getProviders()
          .flatMap { it.entries }
          .filter { it.key.toString().startsWith(SIGNATURE_OID_PREFIX) }
          .forEach { entry ->
            val name = entry.value.toString()
            val oid = entry.key.toString().removePrefix(SIGNATURE_OID_PREFIX)
            putIfAbsent(name, SignatureAlgo(name, oid))
          }
    }
  }

  /** Creates a CSR from an X.500 name string, signing with the given [keyPair]. */
  fun create(
      x500Name: String,
      algorithmName: String,
      keyPair: KeyPair,
      sans: List<San> = emptyList(),
  ): CsrRequest {
    val info = CsrInfo(X500Principal(x500Name), keyPair.public, sans)
    val algorithm =
        signatureAlgorithms[algorithmName] ?: error("Unknown signature algorithm '$algorithmName'")
    return CsrRequest(info, algorithm, sign(info, algorithm, keyPair.private))
  }

  /** Creates a CSR by signing the given [info] with the [privateKey]. */
  fun create(info: CsrInfo, algorithm: SignatureAlgo, privateKey: PrivateKey): CsrRequest =
      CsrRequest(info, algorithm, sign(info, algorithm, privateKey))

  private fun sign(info: CsrInfo, algorithm: SignatureAlgo, privateKey: PrivateKey): ByteArray =
      Signature.getInstance(algorithm.name)
          .apply {
            initSign(privateKey)
            update(info.encoded)
          }
          .sign()
}
