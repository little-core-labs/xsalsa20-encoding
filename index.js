const xsalsa20 = require('xsalsa20')
const blake2b = require('blake2b')
const crypto = require('crypto')
const assert = require('assert')

class DefaultEncoding {
  encode(value) { return value }
  decode(value) { return value }
}

function createCodec(key, opts) {
  if (!opts || 'object' !== typeof opts) {
    opts = {}
  }

  assert(Buffer.isBuffer(key), 'key should be a buffer')
  assert(32 >= key.length, 'key should be 32 bytes')
  assert('object' === typeof opts, 'options should be an object')

  const {
    valueEncoding = new DefaultEncoding()
  } = opts

  key = key.slice(0, 32)

  encode.bytes = 0
  decode.bytes = 0

  return {
    encodingLength,
    valueEncoding,
    encode,
    decode,
    key,
  }

  function encode(value, buffer, offset)  {
    const encodedValue = valueEncoding.encode(value)
    const plaintext = toBuffer(encodedValue)
    const length = encodingLength(plaintext)

    assert(Buffer.isBuffer(plaintext), 'cannot convert plaintext to a buffer')
    assert(plaintext.length, 'cannot encode empty plaintext buffer')

    if (!Buffer.isBuffer(buffer)) {
      buffer = Buffer.alloc(length)
    }

    if (!offset || 'number' !== typeof offset) {
      offset = 0
    }

    const ciphertext = buffer.slice(offset + 24)
    const nonce = buffer.slice(offset)

    assert(ciphertext.length >= length - 24,
      'cannot store ciphertext in buffer at offset.')

    crypto.randomBytes(24).copy(nonce)

    const xor = xsalsa20(nonce, key)

    xor.update(plaintext, ciphertext)
    xor.finalize()

    encode.bytes = length
    return buffer.slice(offset, offset + length)
  }

  function decode(buffer, start, end) {
    if (!start || 'number' !== typeof start) {
      start = 0
    }

    if (!end || 'number' !== typeof end) {
      end = buffer.length
    }

    assert(Buffer.isBuffer(buffer), 'cannot decode non-buffer')

    const ciphertext = buffer.slice(start + 24, end)
    const length = encodingLength(ciphertext)

    if (0 === length) {
      throw new RangeError('Cannot decode empty ciphertext at offset.')
    }

    const plaintext = Buffer.allocUnsafe(length - 24)
    const nonce = buffer.slice(start, start + 24)
    const xor = xsalsa20(nonce, key)

    xor.update(ciphertext, plaintext)
    xor.finalize()

    decode.bytes = length

    const decodedValue = valueEncoding.decode(plaintext, 0)

    return decodedValue
  }
}

function encodingLength(value) {
  const buffer = toBuffer(value)
  return buffer && buffer.length ? 24 + buffer.length : 0
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value
  }

  if ('string' === typeof value) {
    return Buffer.from(value)
  }

  if (Array.isArray(value)) {
    return Buffer.from(value)
  }

  if (value && 'object' === typeof value && 'Buffer' === value.type) {
    if (Array.isArray(value.data)) {
      return Buffer.from(value.data)
    }
  }

  return null
}

module.exports = createCodec
