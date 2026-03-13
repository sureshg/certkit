package certkit.pem

import certkit.der.seq
import java.security.AlgorithmParameters
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateCrtKey
import javax.crypto.Cipher
import javax.crypto.EncryptedPrivateKeyInfo
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.PBEParameterSpec

/**
 * PBE algorithm identifiers for PKCS#8 encryption.
 * - **v1 (SHA-1 + 3DES)** — Max compatibility. OpenSSL: `pkcs8 -topk8 -v1 PBE-SHA1-3DES`
 * - **v1 (MD5 + DES)** — Legacy compatibility. OpenSSL: `pkcs8 -topk8 -v1 PBE-MD5-DES`
 * - **v2** — PBKDF2(HMAC-SHA256) + AES-256-CBC. OpenSSL: `pkcs8 -topk8 -v2 aes-256-cbc`
 */
object Pkcs8Algo {
  const val V1_SHA1_3DES = "PBEWithSHA1AndDESede"
  const val V1_MD5_DES = "PBEWithMD5AndDES"
  const val V2_AES_256_CBC = "PBEWithHmacSHA256AndAES_256"

  fun isV1(algorithm: String) = algorithm == V1_SHA1_3DES || algorithm == V1_MD5_DES
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
fun PrivateKey.toPkcs8Pem(
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

        // v1 params are recognized by EncryptedPrivateKeyInfo; v2 must be re-wrapped as "PBES2"
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
fun PrivateKey.toPkcs1Pem(): String =
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
