const xsalsa20 = require('xsalsa20')
const blake2b = require('blake2b')

function createCodec(nonce, key) {
  if (nonce && key && 32 === nonce.length && 24 === key.length) {
    [ nonce, key ] = [ key, nonce ]
  }

  if (32 === nonce.length && !Buffer.isBuffer(key)) {
    key = nonce
    nonce = Buffer.alloc(24)
    Buffer.from(blake2b(nonce.length).update(key).digest()).copy(nonce)
  }


  if (!Buffer.isBuffer(key)) {
    throw new TypeError('Expecting secret key to be a buffer')
  }

  if (key.length < 32) {
    throw new RangeError('Expecting secret key to be at least 32 bytes')
  }

  if (!Buffer.isBuffer(nonce)) {
    throw new TypeError('Expecting nonce to be a buffer')
  }

  if (nonce.length < 24) {
    throw new RangeError('Expecting nonce to be at least 24 bytes')
  }

  nonce = nonce.slice(0, 24)
  key = key.slice(0, 32)

  encode.bytes = 0
  decode.bytes = 0

  return {
    encodingLength,
    encode,
    decode,
    nonce,
    key,
  }

  function encode(value, buffer, offset) {
    const plaintext = toBuffer(value)
    const length = encodingLength(value)

    if (!Buffer.isBuffer(plaintext)) {
      throw new TypeError('Cannot convert value to a buffer')
    }

    if ('number' === typeof buffer) {
      offset = buffer
    }

    if (!Buffer.isBuffer(buffer)) {
      buffer = Buffer.alloc(length)
    }

    if (!offset || 'number' !== typeof offset) {
      offset = 0
    }

    const ciphertext = buffer.slice(offset)

    if (ciphertext.length < length) {
      throw new RangeError('Cannot store ciphertext in buffer at offset.')
    }

    const xor = xsalsa20(nonce, key)

    xor.update(plaintext, ciphertext)
    xor.finalize()

    encode.bytes = length
    return ciphertext
  }

  function decode(buffer, offset) {
    if (!offset || 'number' !== typeof offset) {
      offset = 0
    }

    if (!Buffer.isBuffer(buffer)) {
      throw new TypeError('Expecting decode input to be a buffer.')
    }

    const ciphertext = buffer.slice(offset)
    const length = encodingLength(ciphertext)

    if (0 === length) {
      throw new RangeError('Cannot decode empty ciphertext at offset.')
    }

    const plaintext = Buffer.allocUnsafe(length)
    const xor = xsalsa20(nonce, key)

    xor.update(ciphertext, plaintext)
    xor.finalize()

    decode.bytes = length
    return plaintext
  }
}

function encodingLength(value) {
  const buffer = toBuffer(value)
  return buffer ? buffer.length : 0
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

  if (value && 'object' === value && 'Buffer' === value.type) {
    if (Array.isArray(value.data)) {
      return Buffer.from(value.data)
    }
  }

  return null
}

module.exports = createCodec
