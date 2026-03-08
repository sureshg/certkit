package certkit.der

import java.math.BigInteger
import kotlin.time.Instant
import kotlinx.io.*

@DslMarker annotation class DerDsl

@DerDsl
class DerBuilder {
  internal val elements = mutableListOf<ByteArray>()

  fun boolean(value: Boolean) {
    elements += Der.boolean(value)
  }

  fun bitString(padBits: Int, value: ByteArray) {
    elements += Der.bitString(padBits, value)
  }

  fun integer(value: Long) {
    elements += Der.integer(value)
  }

  fun integer(value: BigInteger) {
    elements += Der.integer(value)
  }

  fun nullValue() {
    elements += Der.nullValue
  }

  fun octetString(value: ByteArray) {
    elements += Der.octetString(value)
  }

  fun oid(oid: String) {
    elements += Der.oid(oid)
  }

  fun utcTime(value: String) {
    elements += Der.utcTime(value)
  }

  fun utcTime(value: Instant) {
    elements += Der.utcTime(value)
  }

  fun tag(tag: Int, body: ByteArray) {
    elements += Der.tag(tag, body)
  }

  fun tag(tag: Int, value: String) = tag(tag, value.encodeToByteArray())

  fun implicitTag(tag: Int, body: ByteArray) {
    elements += Der.implicitTag(tag, body)
  }

  fun seq(block: DerBuilder.() -> Unit) {
    elements += certkit.der.seq(block)
  }

  fun set(block: DerBuilder.() -> Unit) {
    elements += certkit.der.set(block)
  }

  fun octetString(block: DerBuilder.() -> Unit) {
    elements += certkit.der.octetString(block)
  }

  fun explicitTag(tag: Int, block: DerBuilder.() -> Unit) {
    elements += certkit.der.explicitTag(tag, block)
  }

  fun raw(value: ByteArray) {
    elements += value
  }
}

private fun der(block: DerBuilder.() -> Unit) = DerBuilder().apply(block).elements.toTypedArray()

fun seq(block: DerBuilder.() -> Unit): ByteArray = Der.sequence(*der(block))

fun set(block: DerBuilder.() -> Unit): ByteArray = Der.set(*der(block))

fun octetString(block: DerBuilder.() -> Unit): ByteArray =
    Der.octetString(Buffer().apply { der(block).forEach { write(it) } }.readByteArray())

fun explicitTag(tag: Int, block: DerBuilder.() -> Unit): ByteArray =
    Der.explicitTag(tag, *der(block))
