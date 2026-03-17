package certkit.pem

import certkit.der.seq
import java.security.AlgorithmParameters
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateCrtKey
import javax.crypto.Cipher
import javax.crypto.EncryptedPrivateKeyInfo
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.PBEParameterSpec
import kotlin.io.encoding.Base64

/**
 * PBE algorithm identifiers for PKCS#8 encryption.
 * - **v1 (SHA-1 + 3DES)** — Max compatibility. OpenSSL: `pkcs8 -topk8 -v1 PBE-SHA1-3DES`
 * - **v1 (MD5 + DES)** — Legacy compatibility. OpenSSL: `pkcs8 -topk8 -v1 PBE-MD5-DES`
 * - **v2** — PBKDF2(HMAC-SHA256) + AES-256-CBC. OpenSSL: `pkcs8 -topk8 -v2 aes-256-cbc`
 */
public object Pkcs8Algo {
  public const val V1_SHA1_3DES: String = "PBEWithSHA1AndDESede"
  public const val V1_MD5_DES: String = "PBEWithMD5AndDES"
  public const val V2_AES_256_CBC: String = "PBEWithHmacSHA256AndAES_256"

  public fun isV1(algorithm: String): Boolean = algorithm == V1_SHA1_3DES || algorithm == V1_MD5_DES
}

/**
 * Exports this [PrivateKey] as a PKCS#8 PEM string.
 * - **Unencrypted** ([password] = `null`): produces `BEGIN PRIVATE KEY` (OpenSSL: `pkcs8 -topk8
 *   -nocrypt`).
 * - **Encrypted** ([password] provided): produces `BEGIN ENCRYPTED PRIVATE KEY` using the given PBE
 *   [algorithm] and [iterationCount] (OpenSSL: `pkcs8 -topk8 -v1`/`-v2`).
 *
 * @param password `null` → unencrypted; non-null → PBE-encrypted with [algorithm].
 * @param algorithm PBE scheme from [Pkcs8Algo]. Ignored when [password] is null.
 * @param iterationCount PBE iterations (default 2048, matches OpenSSL). Ignored when [password] is
 *   null.
 */
public fun PrivateKey.toPkcs8Pem(
    password: String? = null,
    algorithm: String = Pkcs8Algo.V1_SHA1_3DES,
    iterationCount: Int = 2048,
): String =
    when {
      password.isNullOrBlank() -> encoded.encodePem(PKCS8INF)
      else -> {
        val salt = ByteArray(8).also { SecureRandom().nextBytes(it) }
        val pbeSpec = PBEParameterSpec(salt, iterationCount)
        val secretKey =
            SecretKeyFactory.getInstance(algorithm)
                .generateSecret(PBEKeySpec(password.toCharArray()))
        val cipher =
            Cipher.getInstance(algorithm).apply { init(Cipher.ENCRYPT_MODE, secretKey, pbeSpec) }
        val ciphertext = cipher.doFinal(encoded)

        // v1 params are recognized by EncryptedPrivateKeyInfo directly;
        // v2 (PBES2, RFC 8018 §6.2) derives a symmetric key from password + salt + iteration count
        // via PBKDF2(HMAC-SHA256), then encrypts with AES-256-CBC — must be re-wrapped as "PBES2"
        // for standard ASN.1 encoding.
        val params =
            when {
              Pkcs8Algo.isV1(algorithm) -> cipher.parameters
              else ->
                  AlgorithmParameters.getInstance("PBES2").apply { init(cipher.parameters.encoded) }
            }

        EncryptedPrivateKeyInfo(params, ciphertext).encoded.encodePem(PKCS8)
      }
    }

/**
 * Converts an RSA private key to PKCS#1 PEM (`BEGIN RSA PRIVATE KEY`).
 *
 * PKCS#1 (RFC 8017 §A.1.2) stores raw RSA components (n, e, d, p, q, CRT coefficients) without an
 * algorithm identifier wrapper. Equivalent to `openssl rsa -out key.pem`.
 *
 * Requires an [RSAPrivateCrtKey], which is the standard JDK representation for RSA key pairs.
 *
 * @throws IllegalStateException if the key is not an [RSAPrivateCrtKey].
 */
public fun PrivateKey.toPkcs1Pem(): String =
    when (this) {
      is RSAPrivateCrtKey ->
          seq {
                integer(0)
                integer(modulus)
                integer(publicExponent)
                integer(privateExponent)
                integer(primeP)
                integer(primeQ)
                integer(primeExponentP)
                integer(primeExponentQ)
                integer(crtCoefficient)
              }
              .encodePem(PemType.PKCS1)
      else -> error("PKCS#1 PEM export is only supported for RSA keys, got $algorithm")
    }

/** PEM bundle parsed from a keystore (PKCS#12 or JKS). */
public data class PemBundle(
    val key: String,
    val cert: String,
    val certChain: String,
    val keyPass: String? = null,
)

/**
 * Parses a Base64-encoded keystore (PKCS#12 or JKS) and returns a PEM-encoded bundle.
 *
 * @param data Base64-encoded keystore data (PKCS#12 or JKS).
 * @param storePass password to unlock the keystore.
 * @param storeType keystore type — `"PKCS12"` (default) or `"JKS"`.
 * @param keyPass if non-null, the exported key is PBE-encrypted with this password.
 * @param pkcs1 `true` → PKCS#1 RSA PEM; `false` (default) → PKCS#8 PEM.
 */
public fun parseKeyStore(
    data: String,
    storePass: String,
    storeType: String = "PKCS12",
    keyPass: String? = null,
    pkcs1: Boolean = false,
): PemBundle {
  val ks =
      KeyStore.getInstance(storeType).apply {
        load(Base64.decode(data).inputStream(), storePass.toCharArray())
      }

  val alias =
      ks.aliases().toList().firstOrNull { ks.isKeyEntry(it) }
          ?: error("${ks.type}: no private key found")

  val key = ks.getKey(alias, storePass.toCharArray()) as PrivateKey
  val cert =
      ks.getCertificate(alias) as? X509Certificate ?: error("${ks.type}: no certificate found")
  val caCerts = ks.getCertificateChain(alias).map { it as X509Certificate }.filter { it != cert }

  require(caCerts.isNotEmpty()) { "${ks.type}: no CA certificates found in chain" }

  return PemBundle(
      key = if (pkcs1) key.toPkcs1Pem() else key.toPkcs8Pem(password = keyPass),
      cert = cert.pem,
      certChain = caCerts.joinToString("") { it.pem },
      keyPass = keyPass,
  )
}
