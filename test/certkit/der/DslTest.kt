package certkit.der

import certkit.cert.Cert
import certkit.cert.San
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertContentEquals

class DslTest {

  @Test
  fun `seq encodes sequence`() {
    val expected = Der.sequence(Der.integer(0L), Der.oid("1.2.840.113549.1.1.11"), Der.nullValue)
    val actual = seq {
      integer(0L)
      oid("1.2.840.113549.1.1.11")
      nullValue()
    }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `set encodes set with nested seq`() {
    val expected = Der.set(Der.sequence(Der.oid("2.5.4.3"), Der.tag(12, "Bob".encodeToByteArray())))
    val actual = set {
      seq {
        oid("2.5.4.3")
        tag(12, "Bob")
      }
    }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `explicitTag wraps inner elements`() {
    val expected = Der.explicitTag(3, Der.sequence(Der.oid("2.5.29.17")))
    val actual = explicitTag(3) { seq { oid("2.5.29.17") } }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `nested seq encodes correctly`() {
    val expected =
        Der.sequence(Der.sequence(Der.oid("2.5.4.3"), Der.tag(12, "Alice".encodeToByteArray())))
    val actual = seq {
      seq {
        oid("2.5.4.3")
        tag(12, "Alice")
      }
    }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `implicitTag encodes context tag`() {
    val expected = Der.sequence(Der.implicitTag(0, byteArrayOf(0x01, 0x02)))
    val actual = seq { implicitTag(0, byteArrayOf(0x01, 0x02)) }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `raw injects prebuilt bytes`() {
    val prebuilt = Der.oid("1.2.3.4")
    val expected = Der.sequence(prebuilt, Der.integer(1L))
    val actual = seq {
      raw(prebuilt)
      integer(1L)
    }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `boolean and octetString encode`() {
    val expected = Der.sequence(Der.boolean(true), Der.octetString(byteArrayOf(0xCA.toByte())))
    val actual = seq {
      boolean(true)
      octetString(byteArrayOf(0xCA.toByte()))
    }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `bitString encodes with pad bits`() {
    val data = byteArrayOf(0xFF.toByte(), 0x80.toByte())
    val expected = Der.sequence(Der.bitString(1, data))
    val actual = seq { bitString(1, data) }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `utcTime encodes time range`() {
    val expected = Der.sequence(Der.utcTime("240101000000Z"), Der.utcTime("251231235959Z"))
    val actual = seq {
      utcTime("240101000000Z")
      utcTime("251231235959Z")
    }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `tag encodes string value`() {
    val expected = Der.sequence(Der.tag(12, "Hello".encodeToByteArray()))
    val actual = seq { tag(12, "Hello") }
    assertContentEquals(expected, actual)
  }

  @Test
  fun `self-signed TBS structure`() {
    val kp =
        KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
    val pub = kp.public as ECPublicKey

    val issuer = X500Principal("CN=Test,O=TestOrg")
    val notBefore = "240101000000Z"
    val notAfter = "251231235959Z"
    val sans = listOf(San.Dns("localhost"), San.Ip("127.0.0.1"))

    val pubKeyHash = Cert.hashPublicKey(pub)
    val sanEntries = sans.map { it.toDer() }

    val expected =
        Der.sequence(
            Der.explicitTag(0, Der.integer(2)),
            Der.integer(1L),
            Der.sequence(Der.oid("1.2.840.10045.4.3.2"), Der.nullValue),
            issuer.encoded,
            Der.sequence(Der.utcTime(notBefore), Der.utcTime(notAfter)),
            issuer.encoded,
            pub.encoded,
            Der.explicitTag(
                3,
                Der.sequence(
                    Der.sequence(
                        Der.oid("2.5.29.14"),
                        Der.octetString(Der.octetString(pubKeyHash)),
                    ),
                    Der.sequence(
                        Der.oid("2.5.29.35"),
                        Der.octetString(Der.sequence(Der.implicitTag(0, pubKeyHash))),
                    ),
                    Der.sequence(
                        Der.oid("2.5.29.19"),
                        Der.boolean(true),
                        Der.octetString(Der.sequence(Der.boolean(true))),
                    ),
                    Der.sequence(
                        Der.oid("2.5.29.17"),
                        Der.octetString(Der.sequence(*sanEntries.toTypedArray())),
                    ),
                ),
            ),
        )

    val actual = seq {
      explicitTag(0) { integer(2L) }
      integer(1L)
      seq {
        oid("1.2.840.10045.4.3.2")
        nullValue()
      }
      raw(issuer.encoded)
      seq {
        utcTime(notBefore)
        utcTime(notAfter)
      }
      raw(issuer.encoded)
      raw(pub.encoded)
      explicitTag(3) {
        seq {
          seq {
            oid("2.5.29.14")
            octetString { octetString(pubKeyHash) }
          }
          seq {
            oid("2.5.29.35")
            octetString { seq { implicitTag(0, pubKeyHash) } }
          }
          seq {
            oid("2.5.29.19")
            boolean(true)
            octetString { seq { boolean(true) } }
          }
          seq {
            oid("2.5.29.17")
            octetString { seq { sans.forEach { raw(it.toDer()) } } }
          }
        }
      }
    }

    assertContentEquals(expected, actual)
  }
}
