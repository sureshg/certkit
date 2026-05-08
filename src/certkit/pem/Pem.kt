package certkit.pem

import certkit.der.Der
import certkit.tls.newKeyStore
import java.nio.file.Path
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.EncryptedPrivateKeyInfo
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.path.readText

/**
 * PEM block type markers.
 *
 * [pem.h](https://github.com/openssl/openssl/blob/master/include/openssl/pem.h#L35)
 */
public enum class PemType(public val marker: String) {
  X509("CERTIFICATE"),
  X509_REQ("CERTIFICATE REQUEST"),
  X509_CRL("X509 CRL"),
  PUBLIC("PUBLIC KEY"),
  PKCS1("RSA PRIVATE KEY"),
  RSA_PUBLIC("RSA PUBLIC KEY"),
  DSA("DSA PRIVATE KEY"),
  DSA_PUBLIC("DSA PUBLIC KEY"),
  PKCS8("ENCRYPTED PRIVATE KEY"),
  PKCS8INF("PRIVATE KEY"),
  ECDSA_PUBLIC("ECDSA PUBLIC KEY"),
  EC_PARAMETERS("EC PARAMETERS"),
  EC_PRIVATE_KEY("EC PRIVATE KEY"),
}

/** Reads and loads PEM-encoded certificates, private keys, public keys, and key/trust stores. */
public object Pem {

  private val CERT_PATTERN =
      """-+BEGIN\s+.*CERTIFICATE[^-]*-+\s+([a-z0-9+/=\r\n]+)-+END\s+.*CERTIFICATE[^-]*-+"""
          .toRegex(RegexOption.IGNORE_CASE)

  private val PRIVATE_KEY_PATTERN =
      """-+BEGIN\s+(?:(.*)\s+)?PRIVATE\s+KEY[^-]*-+\s+([a-z0-9+/=\r\n]+)-+END\s+.*PRIVATE\s+KEY[^-]*-+"""
          .toRegex(RegexOption.IGNORE_CASE)

  private val PUBLIC_KEY_PATTERN =
      """-+BEGIN\s+(?:(.*)\s+)?PUBLIC\s+KEY[^-]*-+\s+([a-z0-9+/=\r\n]+)-+END\s+.*PUBLIC\s+KEY[^-]*-+"""
          .toRegex(RegexOption.IGNORE_CASE)

  // Test data must be exactly 20 bytes for DSA
  private val TEST_SIGNATURE_DATA = "01234567890123456789".encodeToByteArray()
  private val SUPPORTED_KEY_TYPES = setOf("RSA", "EC", "DSA")

  private val VERSION_0 = byteArrayOf(2, 1, 0)
  private val RSA_KEY_OID = Der.oid("1.2.840.113549.1.1.1")
  private val DSA_KEY_OID = Der.oid("1.2.840.10040.4.1")
  private val EC_KEY_OID = Der.oid("1.2.840.10045.2.1")
  private val DER_NULL = Der.nullValue

  private val certFactory = CertificateFactory.getInstance("X.509")

  /** Returns `true` if the data contains PEM-encoded certificates, keys, or private keys. */
  public fun isPem(path: Path): Boolean = isPem(path.readText(Charsets.US_ASCII))

  /** Returns `true` if the string contains PEM-encoded certificates, keys, or private keys. */
  public fun isPem(data: String): Boolean =
      CERT_PATTERN.containsMatchIn(data) ||
          PUBLIC_KEY_PATTERN.containsMatchIn(data) ||
          PRIVATE_KEY_PATTERN.containsMatchIn(data)

  /** Reads all PEM-encoded X.509 certificates from the given file. */
  public fun readCertificateChain(path: Path): List<X509Certificate> =
      readCertificateChain(path.readText(Charsets.US_ASCII))

  /** Reads all PEM-encoded X.509 certificates from the given string. */
  public fun readCertificateChain(pem: String): List<X509Certificate> =
      CERT_PATTERN.findAll(pem)
          .map {
            val der = Base64.Mime.decode(it.groupValues[1].encodeToByteArray())
            certFactory.generateCertificate(der.inputStream()) as X509Certificate
          }
          .toList()

  /** Loads a PKCS#12 trust store from a PEM certificate chain file. */
  public fun loadTrustStore(path: Path): KeyStore {
    val keyStore = newKeyStore()
    for (cert in readCertificateChain(path)) {
      keyStore.setCertificateEntry(cert.subjectX500Principal.getName("RFC2253"), cert)
    }
    return keyStore
  }

  /**
   * Loads a PKCS#12 [KeyStore] from PEM-encoded certificate chain and private key files.
   *
   * The resulting key store contains a single private key entry ("key") that bundles:
   * 1. The private key (from [privateKeyFile])
   * 2. The full certificate chain (from [certChainFile]) — ordered as `[leaf, intermediate CA(s)…,
   *    root CA]`
   * 3. An optional password protecting the key entry
   *
   * PKCS#12 requires the leaf certificate (whose public key matches the private key) to be at index
   * 0 of the chain, so the function reorders certificates accordingly.
   */
  public fun loadKeyStore(
      certChainFile: Path,
      privateKeyFile: Path,
      keyPassword: String? = null,
      storeKeyWithPassword: Boolean = false,
  ): KeyStore {
    val key = loadPrivateKey(privateKeyFile, keyPassword)
    val chain = readCertificateChain(certChainFile)
    check(chain.isNotEmpty()) {
      "Certificate file does not contain any certificates: $certChainFile"
    }

    val [matched, rest] = chain.partition { matches(key, it) }
    require(matched.isNotEmpty()) { "Private key does not match the public key of any certificate" }
    val certs = matched + rest

    val password = keyPassword?.takeIf { storeKeyWithPassword }.orEmpty()
    return newKeyStore().apply {
      setKeyEntry("key", key, password.toCharArray(), certs.toTypedArray())
    }
  }

  /**
   * Loads a private key from a PEM file.
   *
   * @see loadPrivateKey(String, String?) for supported formats and limitations.
   */
  public fun loadPrivateKey(path: Path, keyPassword: String? = null): PrivateKey =
      loadPrivateKey(path.readText(Charsets.US_ASCII), keyPassword)

  /**
   * Loads a private key from a PEM string.
   *
   * Supported formats:
   * - **Unencrypted PKCS#8** (`BEGIN PRIVATE KEY`): Loaded directly via `PKCS8EncodedKeySpec`.
   * - **Encrypted PKCS#8** (`BEGIN ENCRYPTED PRIVATE KEY`): Decrypted with `keyPassword`, then
   *   loaded as PKCS#8.
   * - **Unencrypted PKCS#1** (Legacy OpenSSL format: `BEGIN RSA/DSA/EC PRIVATE KEY`): Converted
   *   internally to PKCS#8, then loaded.
   * - **Encrypted PKCS#1** (Legacy OpenSSL format: `BEGIN [TYPE] PRIVATE KEY` with `Proc-Type:
   *   4,ENCRYPTED`): **Not Supported**. Throws an error if detected.
   *
   * All supported formats are converted to unencrypted PKCS#8 before loading, resulting in a
   * [PrivateKey] containing raw decrypted material without storing the password.
   *
   * @param pem The PEM-encoded private key string.
   * @param keyPassword Optional password for encrypted PKCS#8 keys.
   * @return The loaded [PrivateKey] containing decrypted, raw key material in PKCS#8 format.
   */
  public fun loadPrivateKey(pem: String, keyPassword: String? = null): PrivateKey {
    val match = PRIVATE_KEY_PATTERN.find(pem) ?: error("did not find a private key")
    val keyType = match.groupValues[1].ifEmpty { null }
    val base64Key = match.groupValues[2]

    if (base64Key.lowercase().startsWith("proc-type")) {
      error("Password protected PKCS#1 private keys are not supported")
    }

    val encodedKey = Base64.Mime.decode(base64Key.encodeToByteArray())

    return when (keyType) {
      null -> generatePrivateKey(PKCS8EncodedKeySpec(encodedKey))
      "ENCRYPTED" -> {
        if (keyPassword == null) error("Private key is encrypted, but no password was provided")
        val info = EncryptedPrivateKeyInfo(encodedKey)
        val secretKey =
            SecretKeyFactory.getInstance(info.algName)
                .generateSecret(PBEKeySpec(keyPassword.toCharArray()))
        val cipher =
            Cipher.getInstance(info.algName).apply {
              init(Cipher.DECRYPT_MODE, secretKey, info.algParameters)
            }
        generatePrivateKey(info.getKeySpec(cipher))
      }
      else -> loadPkcs1PrivateKey(keyType, encodedKey)
    }
  }

  /** Loads a public key from a PEM file. Supports PKCS#8 and RSA PKCS#1 formats. */
  public fun loadPublicKey(path: Path): PublicKey = loadPublicKey(path.readText(Charsets.US_ASCII))

  /** Loads a public key from a PEM string. Supports PKCS#8 and RSA PKCS#1 formats. */
  public fun loadPublicKey(pem: String): PublicKey {
    val match = PUBLIC_KEY_PATTERN.find(pem) ?: error("did not find a public key")
    val keyType = match.groupValues[1].ifEmpty { null }
    val encodedKey = Base64.Mime.decode(match.groupValues[2].encodeToByteArray())

    return when (keyType) {
      null -> generatePublicKey(X509EncodedKeySpec(encodedKey))
      "RSA" -> {
        val pkcs8 = rsaPublicKeyPkcs1ToPkcs8(encodedKey)
        KeyFactory.getInstance(keyType).generatePublic(X509EncodedKeySpec(pkcs8))
      }
      else -> error("$keyType public key in PKCS 1 format is not supported")
    }
  }

  private fun rsaPublicKeyPkcs1ToPkcs8(pkcs1: ByteArray): ByteArray =
      Der.sequence(Der.sequence(RSA_KEY_OID, DER_NULL), Der.bitString(0, pkcs1))

  private fun rsaPkcs1ToPkcs8(pkcs1: ByteArray): ByteArray =
      Der.sequence(VERSION_0, Der.sequence(RSA_KEY_OID, DER_NULL), Der.octetString(pkcs1))

  private fun dsaPkcs1ToPkcs8(pkcs1: ByteArray): ByteArray {
    val elements = Der.decodeSequence(pkcs1)
    require(elements.size == 6) { "Expected DSA key to have 6 elements" }
    val keyId = Der.sequence(DSA_KEY_OID, Der.sequence(elements[1], elements[2], elements[3]))
    return Der.sequence(VERSION_0, keyId, Der.octetString(elements[5]))
  }

  private fun ecPkcs1ToPkcs8(pkcs1: ByteArray): ByteArray {
    val elements = Der.decodeSequence(pkcs1)
    require(elements.size == 4) { "Expected EC key to have 4 elements" }
    val curveOid = Der.decodeExplicitTag(elements[2])
    val keyId = Der.sequence(EC_KEY_OID, curveOid)
    return Der.sequence(
        VERSION_0,
        keyId,
        Der.octetString(Der.sequence(elements[0], elements[1], elements[3])),
    )
  }

  private fun generatePrivateKey(spec: PKCS8EncodedKeySpec): PrivateKey =
      SUPPORTED_KEY_TYPES.firstNotNullOfOrNull { algo ->
        runCatching { KeyFactory.getInstance(algo).generatePrivate(spec) }.getOrNull()
      } ?: error("Key type must be one of $SUPPORTED_KEY_TYPES")

  private fun generatePublicKey(spec: X509EncodedKeySpec): PublicKey =
      SUPPORTED_KEY_TYPES.firstNotNullOfOrNull { algo ->
        runCatching { KeyFactory.getInstance(algo).generatePublic(spec) }.getOrNull()
      } ?: error("Key type must be one of $SUPPORTED_KEY_TYPES")

  private fun loadPkcs1PrivateKey(pkcs1KeyType: String, pkcs1Key: ByteArray): PrivateKey {
    val pkcs8Key =
        when (pkcs1KeyType) {
          "RSA" -> rsaPkcs1ToPkcs8(pkcs1Key)
          "DSA" -> dsaPkcs1ToPkcs8(pkcs1Key)
          "EC" -> ecPkcs1ToPkcs8(pkcs1Key)
          else -> error("$pkcs1KeyType private key in PKCS 1 format is not supported")
        }
    return KeyFactory.getInstance(pkcs1KeyType).generatePrivate(PKCS8EncodedKeySpec(pkcs8Key))
  }

  private fun matches(privateKey: PrivateKey, certificate: Certificate): Boolean =
      try {
        val publicKey = certificate.publicKey
        val signer = signatureFor(privateKey, publicKey)
        signer.initSign(privateKey)
        signer.update(TEST_SIGNATURE_DATA)
        val sig = signer.sign()
        signer.initVerify(publicKey)
        signer.update(TEST_SIGNATURE_DATA)
        signer.verify(sig)
      } catch (_: GeneralSecurityException) {
        false
      }

  private fun signatureFor(privateKey: PrivateKey, publicKey: PublicKey): Signature =
      when (privateKey) {
        is RSAPrivateKey if publicKey is RSAPublicKey -> Signature.getInstance("NONEwithRSA")
        is ECPrivateKey if publicKey is ECPublicKey -> Signature.getInstance("NONEwithECDSA")
        is DSAKey if publicKey is DSAKey -> Signature.getInstance("NONEwithDSA")
        else -> error("Key type must be one of $SUPPORTED_KEY_TYPES")
      }
}
