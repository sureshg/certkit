package certkit.der

import certkit.cert.San
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertContentEquals

class DslTest {

  @Test
  fun `seq produces same bytes as Der sequence`() {
    val expected =
        Der.sequence(
            Der.integer(0L),
            Der.oid("1.2.840.113549.1.1.11"),
            Der.nullValue(),
        )
    val actual = seq {
      integer(0L)
      oid("1.2.840.113549.1.1.11")
      nullValue()
    }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `set produces same bytes as Der set`() {
    val expected =
        Der.set(
            Der.sequence(Der.oid("2.5.4.3"), Der.tag(12, "Bob".encodeToByteArray())),
        )
    val actual = set {
      seq {
        oid("2.5.4.3")
        tag(12, "Bob")
      }
    }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `explicitTag produces same bytes as Der explicitTag`() {
    val inner = Der.sequence(Der.oid("2.5.29.17"))
    val expected = Der.explicitTag(3, inner)
    val actual = explicitTag(3) { seq { oid("2.5.29.17") } }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `nested sequence produces correct DER structure`() {
    val expected =
        Der.sequence(
            Der.sequence(
                Der.oid("2.5.4.3"),
                Der.tag(12, "Alice".encodeToByteArray()),
            ),
        )
    val actual = seq {
      seq {
        oid("2.5.4.3")
        tag(12, "Alice")
      }
    }
    assertContentEquals(expected, actual)
  }

  /**
   * Replicates the exact DER structure built by [certkit.cert.Cert.buildSelfSigned] using the DSL
   * and asserts that both approaches produce identical byte arrays for the TBS certificate.
   */
  @Test
  fun `DSL produces identical bytes to Der calls for self-signed cert structure`() {
    val keyPair = genECKeyPair()
    val pub = keyPair.public as ECPublicKey

    val issuer = X500Principal("CN=Test,O=TestOrg")
    val subject = issuer
    val notBefore = "240101000000Z"
    val notAfter = "251231235959Z"
    val sans = listOf(San.Dns("localhost"), San.Ip("127.0.0.1"))

    val pubKeyHash = hashPublicKey(pub)
    val sanEntries = sans.map { it.toDer() }

    val sha256EcdsaOid = Der.oid("1.2.840.10045.4.3.2")
    val subjectKeyIdOid = Der.oid("2.5.29.14")
    val authorityKeyIdOid = Der.oid("2.5.29.35")
    val basicConstraintsOid = Der.oid("2.5.29.19")
    val subjectAltNameOid = Der.oid("2.5.29.17")

    val sigAlgRef = Der.sequence(sha256EcdsaOid, Der.nullValue())

    val tbsRef =
        Der.sequence(
            Der.explicitTag(0, Der.integer(2)),
            Der.integer(1L),
            sigAlgRef,
            issuer.encoded,
            Der.sequence(Der.utcTime(notBefore), Der.utcTime(notAfter)),
            subject.encoded,
            pub.encoded,
            Der.explicitTag(
                3,
                Der.sequence(
                    Der.sequence(subjectKeyIdOid, Der.octetString(Der.octetString(pubKeyHash))),
                    Der.sequence(
                        authorityKeyIdOid,
                        Der.octetString(Der.sequence(Der.implicitTag(0, pubKeyHash))),
                    ),
                    Der.sequence(
                        basicConstraintsOid,
                        Der.boolean(true),
                        Der.octetString(Der.sequence(Der.boolean(true))),
                    ),
                    Der.sequence(
                        subjectAltNameOid,
                        Der.octetString(Der.sequence(*sanEntries.toTypedArray())),
                    ),
                ),
            ),
        )

    val sigAlgDsl = seq {
      oid("1.2.840.10045.4.3.2")
      nullValue()
    }

    val tbsDsl = seq {
      explicitTag(0) { integer(2L) }
      integer(1L)
      raw(sigAlgDsl)
      raw(issuer.encoded)
      seq {
        utcTime(notBefore)
        utcTime(notAfter)
      }
      raw(subject.encoded)
      raw(pub.encoded)
      explicitTag(3) {
        seq {
          seq {
            oid("2.5.29.14")
            octetString(Der.octetString(pubKeyHash))
          }
          seq {
            oid("2.5.29.35")
            octetString(certkit.der.seq { implicitTag(0, pubKeyHash) })
          }
          seq {
            oid("2.5.29.19")
            boolean(true)
            octetString(certkit.der.seq { boolean(true) })
          }
          seq {
            oid("2.5.29.17")
            octetString(certkit.der.seq { sanEntries.forEach { raw(it) } })
          }
        }
      }
    }

    assertContentEquals(tbsRef, tbsDsl, "TBS certificate bytes differ between Der and DSL")
  }

  private fun genECKeyPair(): KeyPair =
      KeyPairGenerator.getInstance("EC")
          .apply { initialize(ECGenParameterSpec("secp256r1")) }
          .generateKeyPair()

  private fun hashPublicKey(key: ECPublicKey): ByteArray {
    val raw = Der.sequence(Der.integer(key.w.affineX), Der.integer(key.w.affineY))
    return MessageDigest.getInstance("SHA-1").digest(raw)
  }
}
