package certkit.der

import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.format
import kotlinx.datetime.format.char
import kotlinx.datetime.toLocalDateTime
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import java.math.BigInteger
import kotlin.time.Instant

/**
 * ASN.1 DER encoder/decoder for PEM processing and certificate signing requests.
 *
 * Based on [airlift/security](https://github.com/airlift/airlift/tree/master/security) DerUtils.
 */
object Der {

  private const val SEQUENCE_TAG = 0x30
  private const val BOOLEAN_TAG = 0x01
  private const val INTEGER_TAG = 0x02
  private const val BIT_STRING_TAG = 0x03
  private const val OCTET_STRING_TAG = 0x04
  private const val NULL_TAG = 0x05
  private const val OBJECT_IDENTIFIER_TAG = 0x06
  private const val UTC_TIME_TAG = 0x17

  /** ASN.1 UTC time format: yyMMddHHmmssZ (2-digit year per X.680) */
  private val UTC_TIME_FORMAT =
      LocalDateTime.Format {
        yearTwoDigits(2000)
        monthNumber()
        day()
        hour()
        minute()
        second()
        char('Z')
      }

  /** Encodes a DER SEQUENCE from the given encoded values. */
  fun sequence(vararg values: ByteArray): ByteArray = constructed(SEQUENCE_TAG, values)

  /** Encodes a DER BIT STRING with the given pad bits and value. */
  fun bitString(padBits: Int, value: ByteArray): ByteArray {
    require(padBits in 0..7) { "Invalid pad bits: $padBits" }
    return Buffer()
        .apply {
          writeByte(BIT_STRING_TAG.toByte())
          writeLength(value.size + 1)
          writeByte(padBits.toByte())
          write(value)
        }
        .readByteArray()
  }

  /** Encodes a DER BOOLEAN TRUE value. */
  fun booleanTrue(): ByteArray = byteArrayOf(BOOLEAN_TAG.toByte(), 0x01, 0xFF.toByte())

  /** Encodes a DER INTEGER from a Long. */
  fun integer(value: Long): ByteArray = integer(BigInteger.valueOf(value))

  /** Encodes a DER INTEGER from a BigInteger. */
  fun integer(value: BigInteger): ByteArray = tag(INTEGER_TAG, value.toByteArray())

  /** Encodes a DER OCTET STRING. */
  fun octetString(value: ByteArray): ByteArray = tag(OCTET_STRING_TAG, value)

  /** Encodes a DER UTC TIME from a raw string. */
  fun utcTime(value: String): ByteArray = tag(UTC_TIME_TAG, value.encodeToByteArray())

  /** Encodes a DER UTC TIME from an [Instant]. */
  fun utcTime(value: Instant): ByteArray =
      tag(
          UTC_TIME_TAG,
          value.toLocalDateTime(TimeZone.UTC).format(UTC_TIME_FORMAT).encodeToByteArray(),
      )

  /** Encodes a DER OBJECT IDENTIFIER from a dotted OID string (e.g. "1.2.840.113549.1.1.1"). */
  fun oid(oid: String): ByteArray {
    val parts = oid.split('.').map { it.toInt() }
    require(parts.size >= 2) { "OID requires at least 2 parts" }
    val body =
        Buffer()
            .apply {
              writeByte((parts[0] * 40 + parts[1]).toByte())
              parts.subList(2, parts.size).forEach { writeOidVarint(it) }
            }
            .readByteArray()
    return Buffer()
        .apply {
          writeByte(OBJECT_IDENTIFIER_TAG.toByte())
          writeLength(body.size)
          write(body)
        }
        .readByteArray()
  }

  /** Encodes a DER NULL. */
  fun derNull(): ByteArray = byteArrayOf(NULL_TAG.toByte(), 0x00)

  /** Encodes a primitive DER tag (0-31) with the given body. */
  fun tag(tag: Int, body: ByteArray): ByteArray {
    require(tag in 0..31) { "Invalid tag: $tag" }
    return writeTag(tag, body)
  }

  /** Encodes a context-specific implicit tag (class bit 0x80 set). */
  fun contextTag(tag: Int, body: ByteArray): ByteArray {
    require(tag in 0..31) { "Invalid tag: $tag" }
    return writeTag(tag or 0x80, body)
  }

  /** Encodes a context-specific constructed SEQUENCE (class bits 0xA0 set). */
  fun contextSequence(tag: Int, vararg values: ByteArray): ByteArray {
    require(tag in 0..31) { "Invalid tag: $tag" }
    return constructed(tag or 0xA0, values)
  }

  /** Decodes a DER SEQUENCE into its constituent elements. */
  fun decodeSequence(data: ByteArray): List<ByteArray> {
    require(data[0].toInt() == SEQUENCE_TAG) { "Expected sequence tag" }
    val (dataLength, headerSize) = decodeLengthAt(data, 1)
    val dataStart = 1 + headerSize
    require(dataLength + dataStart == data.size) { "Invalid sequence" }

    return buildList {
      var pos = dataStart
      while (pos < data.size) {
        val elementStart = pos
        pos++ // skip tag
        val (len, lenSize) = decodeLengthAt(data, pos)
        pos += lenSize + len
        add(data.copyOfRange(elementStart, pos))
      }
    }
  }

  /** Decodes a context-specific optional element (tag class 0xA0). */
  fun decodeOptionalElement(element: ByteArray): ByteArray {
    require(element[0].toInt() and 0xE0 == 0xA0) { "Expected optional sequence element tag" }
    val (len, lenSize) = decodeLengthAt(element, 1)
    val dataStart = 1 + lenSize
    require(len + dataStart == element.size) { "Invalid optional sequence element" }
    return element.copyOfRange(dataStart, dataStart + len)
  }

  /**
   * Decodes a DER length at the given offset, returning (length, bytesConsumed).
   *
   * Short form: single byte < 128. Long form: first byte = 0x80 | numBytes, followed by numBytes of
   * big-endian length.
   */
  private fun decodeLengthAt(buffer: ByteArray, offset: Int): Pair<Int, Int> {
    val firstByte = buffer[offset].toInt() and 0xFF
    require(firstByte != 0x80) { "Indefinite lengths not supported in DER" }
    require(firstByte != 0xFF) { "Invalid length first byte 0xFF" }
    if (firstByte < 128) return firstByte to 1

    val numBytes = firstByte and 0x7F
    require(numBytes <= 4) { "Length encoding too large" }
    val length =
        (0 until numBytes).fold(0) { acc, i ->
          (acc shl 8) or (buffer[offset + 1 + i].toInt() and 0xFF)
        }
    return length to (1 + numBytes)
  }

  private fun writeTag(tag: Int, body: ByteArray): ByteArray {
    require(tag in 0..255) { "Invalid tag: $tag" }
    return Buffer()
        .apply {
          writeByte(tag.toByte())
          writeLength(body.size)
          write(body)
        }
        .readByteArray()
  }

  private fun constructed(tag: Int, values: Array<out ByteArray>): ByteArray {
    val totalLength = values.sumOf { it.size }
    return Buffer()
        .apply {
          writeByte(tag.toByte())
          writeLength(totalLength)
          values.forEach { write(it) }
        }
        .readByteArray()
  }

  /**
   * Writes a DER length encoding directly to this Buffer.
   *
   * Short form (< 128): single byte. Long form: lead byte with high bit set + number of length
   * bytes, then big-endian length.
   */
  private fun Buffer.writeLength(length: Int) {
    if (length < 128) {
      writeByte(length.toByte())
    } else {
      val numBits = 32 - length.countLeadingZeroBits()
      val numBytes = (numBits + 7) / 8
      writeByte((numBytes or 0x80).toByte())
      for (i in numBytes - 1 downTo 0) {
        writeByte((length ushr (i * 8)).toByte())
      }
    }
  }

  /** Writes an OID component as a big-endian base-128 varint to this Buffer. */
  private fun Buffer.writeOidVarint(number: Int) {
    if (number < 128) {
      writeByte(number.toByte())
    } else {
      val numBits = Int.SIZE_BITS - number.countLeadingZeroBits()
      val numParts = (numBits + 6) / 7
      for (i in numParts - 1 downTo 1) {
        writeByte(((number ushr (i * 7)) and 0x7F or 0x80).toByte())
      }
      writeByte((number and 0x7F).toByte())
    }
  }
}
