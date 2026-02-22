package certkit.crl

import certkit.der.Der
import java.security.KeyPair
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal
import kotlin.io.encoding.Base64
import kotlin.time.Instant

/** Parses and builds X.509 Certificate Revocation Lists (CRLs). */
object Crl {

  private val CRL_PATTERN =
      """-+BEGIN\s+X509\s+CRL[^-]*-+[\s\r\n]+([a-z0-9+/=\r\n]+)-+END\s+X509\s+CRL[^-]*-+"""
          .toRegex(RegexOption.IGNORE_CASE)

  private val SHA256_ECDSA_OID = Der.oid("1.2.840.10045.4.3.2")

  private val certFactory = CertificateFactory.getInstance("X.509")

  /** Parses an [X509CRL] from a PEM-encoded string. */
  fun from(pem: String): X509CRL {
    val match = CRL_PATTERN.find(pem) ?: error("No PEM-encoded CRL found")
    val der = Base64.Mime.decode(match.groupValues[1].encodeToByteArray())
    return certFactory.generateCRL(der.inputStream()) as X509CRL
  }

  /** Parses an [X509CRL] from DER-encoded bytes. */
  fun from(bytes: ByteArray): X509CRL = certFactory.generateCRL(bytes.inputStream()) as X509CRL

  /**
   * Builds a minimal X.509 CRL signed with SHA256withECDSA.
   *
   * DER structure ([RFC 5280 §5.1](https://datatracker.ietf.org/doc/html/rfc5280#section-5.1)):
   * ```
   * CertificateList ::= SEQUENCE {
   *   tbsCertList    SEQUENCE { signature, issuer, thisUpdate, [nextUpdate], [revokedCertificates] },
   *   signatureAlgorithm AlgorithmIdentifier,
   *   signatureValue     BIT STRING
   * }
   * ```
   */
  fun build(
      keyPair: KeyPair,
      issuer: X500Principal,
      thisUpdate: Instant,
      nextUpdate: Instant? = null,
      revokedSerials: List<Long> = emptyList(),
  ): X509CRL {
    val sigAlg = Der.sequence(SHA256_ECDSA_OID, Der.nullValue())

    val revoked =
        revokedSerials.map { serial -> Der.sequence(Der.integer(serial), Der.utcTime(thisUpdate)) }

    val tbsComponents = buildList {
      add(sigAlg)
      add(issuer.encoded)
      add(Der.utcTime(thisUpdate))
      if (nextUpdate != null) add(Der.utcTime(nextUpdate))
      if (revoked.isNotEmpty()) add(Der.sequence(*revoked.toTypedArray()))
    }

    val tbsCertList = Der.sequence(*tbsComponents.toTypedArray())

    val sig =
        Signature.getInstance("SHA256withECDSA")
            .apply {
              initSign(keyPair.private)
              update(tbsCertList)
            }
            .sign()

    val crlBytes = Der.sequence(tbsCertList, sigAlg, Der.bitString(0, sig))
    return certFactory.generateCRL(crlBytes.inputStream()) as X509CRL
  }

  /**
   * Returns the CRL Distribution Point URLs from a certificate's extension (OID `2.5.29.31`).
   *
   * ASN.1 structure ([RFC 5280
   * §4.2.1.13](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13)):
   * ```
   * CRLDistributionPoints ::= SEQUENCE OF DistributionPoint
   * DistributionPoint ::= SEQUENCE {
   *   distributionPoint [0] DistributionPointName OPTIONAL, ...
   * }
   * DistributionPointName ::= CHOICE { fullName [0] GeneralNames, ... }
   * GeneralNames ::= SEQUENCE OF GeneralName
   * GeneralName  ::= CHOICE { uniformResourceIdentifier [6] IA5String, ... }
   * ```
   */
  fun distributionPoints(cert: X509Certificate): List<String> =
      cert
          .getExtensionValue("2.5.29.31")
          ?.let { unwrapOctetString(it) }
          ?.let { collectUris(it) }
          .orEmpty()

  /** Unwraps a DER OCTET STRING (tag `0x04`), returning its content bytes (or the input as-is). */
  private fun unwrapOctetString(data: ByteArray): ByteArray =
      if (data.isEmpty() || data[0] != 0x04.toByte()) data
      else data.copyOfRange(1 + derLength(data, 1).second, data.size)

  /**
   * Collects all `uniformResourceIdentifier` (`[6]` / tag `0x86`) strings from DER-encoded data.
   *
   * Walks TLV elements linearly: constructed tags step into content, primitive tags skip past
   * content. Tag `0x86` values are decoded as URI strings.
   */
  private fun collectUris(data: ByteArray): List<String> = buildList {
    var pos = 0
    while (pos < data.size) {
      val tag = data[pos].toInt() and 0xFF
      val (contentLen, headerLen) = derLength(data, pos + 1)
      val contentStart = pos + 1 + headerLen
      if (tag == 0x86) add(String(data, contentStart, contentLen, Charsets.US_ASCII))
      pos = contentStart + if (tag and 0x20 != 0) 0 else contentLen
    }
  }

  /** Returns `(contentLength, headerBytes)` for a DER length field starting at [offset]. */
  private fun derLength(data: ByteArray, offset: Int): Pair<Int, Int> {
    val first = data[offset].toInt() and 0xFF
    return when {
      first < 0x80 -> first to 1
      else -> {
        val n = first and 0x7F
        var len = 0
        for (i in 1..n) len = (len shl 8) or (data[offset + i].toInt() and 0xFF)
        len to (1 + n)
      }
    }
  }
}
