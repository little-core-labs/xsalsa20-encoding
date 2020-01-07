const blake2b = require('blake2b')
const crypto = require('crypto')
const Codec = require('./')
const test = require('tape')
const pbs = require('protocol-buffers')

test('codec = Codec(key)', (t) => {
  const key = crypto.randomBytes(32)
  const codec = Codec(key)

  t.equal(0, Buffer.compare(key, codec.key), 'codec.key')
  t.equal('function', typeof codec.encode, 'codec.encode')
  t.equal('function', typeof codec.decode, 'codec.decode')
  t.equal(0, codec.encode.bytes, 'codec.encode.bytes')
  t.equal(0, codec.decode.bytes, 'codec.decode.bytes')

  t.end()
})

test('codec.encode() | codec.decode()', (t) => {
  const key = crypto.randomBytes(32)
  const codec = Codec(key)

  t.equal(
    0,
    Buffer.compare(
      Buffer.from('hello'),
      codec.decode(codec.encode('hello'))
    ),
    'decodes value from encoded value'
  )

  t.equal(24 + 5, codec.encode.bytes)
  t.equal(24 + 5, codec.decode.bytes)

  t.throws(() => codec.encode(null))
  t.throws(() => codec.encode({}))
  t.throws(() => codec.encode(false))
  t.throws(() => codec.encode(123))
  t.throws(() => codec.encode(''))

  t.throws(() => codec.decode(null))
  t.throws(() => codec.decode({}))
  t.throws(() => codec.decode(Buffer.alloc(0)))
  t.throws(() => codec.decode(Buffer.alloc(24), -1))

  t.ok(codec.encode('hello'))
  t.ok(codec.encode(JSON.parse(JSON.stringify(Buffer.from('hello')))))
  t.ok(codec.encode([ ...Buffer.from('hello') ]))
  t.ok(codec.encode(Buffer.from('hello'), Buffer.alloc(24 + 6), 1))

  t.ok(0 === Buffer.compare(Buffer.from('world'), codec.decode(
    Buffer.concat([ codec.encode('hello'), codec.encode('world') ]),
    codec.encodingLength('hello')
  )))

  t.ok(0 === Buffer.compare(Buffer.from('hello'), codec.decode(
    Buffer.concat([ codec.encode('hello'), codec.encode('world') ]),
    0, codec.encodingLength('hello')
  )))

  t.end()
})

test('codec = Codec(key, { valueEncoding })', (t) => {
  const { Message } = pbs('message Message { string data = 1; }')
  const key = crypto.randomBytes(32)
  const codec = Codec(key, { valueEncoding: Message })
  t.deepEqual(
    { data: 'hello world' },
    codec.decode(codec.encode({ data: 'hello world' })))
  t.end()
})

test('codec.encode() | codec.decode() - detached', (t) => {
  const key = crypto.randomBytes(32)
  const codec = Codec(key)
  const plaintext = Buffer.from('hello')
  const encoded = codec.encode(plaintext)
  const nonce = encoded.slice(0, 24)
  const ciphertext = encoded.slice(24)
  ciphertext.nonce = nonce
  const decoded = codec.decode(ciphertext)
  t.ok(0 === Buffer.compare(plaintext, decoded))
  t.end()
})
