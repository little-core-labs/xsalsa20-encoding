const blake2b = require('blake2b')
const crypto = require('crypto')
const Codec = require('./')
const test = require('tape')
const pbs = require('protocol-buffers')

test('codec = Codec(nonce, key)', (t) => {
  const nonce = crypto.randomBytes(24)
  const key = crypto.randomBytes(32)
  const codec = Codec(nonce, key)

  t.equal(0, Buffer.compare(nonce, codec.nonce), 'codec.nonce')
  t.equal(0, Buffer.compare(key, codec.key), 'codec.key')
  t.equal('function', typeof codec.encode, 'codec.encode')
  t.equal('function', typeof codec.decode, 'codec.decode')
  t.equal(0, codec.encode.bytes, 'codec.encode.bytes')
  t.equal(0, codec.decode.bytes, 'codec.decode.bytes')

  t.end()
})

test('codec = Codec(key, nonce)', (t) => {
  const nonce = crypto.randomBytes(24)
  const key = crypto.randomBytes(32)
  const codec = Codec(key, nonce)

  t.equal(0, Buffer.compare(nonce, codec.nonce), 'codec.nonce')
  t.equal(0, Buffer.compare(key, codec.key), 'codec.key')
  t.end()
})

test('codec = Codec(key)', (t) => {
  const key = crypto.randomBytes(32)
  const nonce = Buffer.alloc(24)
  const codec = Codec(key)
  Buffer.from(blake2b(nonce.length).update(key).digest()).copy(nonce)

  t.equal(0, Buffer.compare(nonce, codec.nonce), 'codec.nonce')
  t.equal(0, Buffer.compare(key, codec.key), 'codec.key')
  t.end()
})

test('buffer = codec.encode(value[, buffer[, offset]])', (t) => {
  const key = Buffer.from('0c05e0034d7c68aa08fed79f8642e10bd79a70c57402a7ecbe81a08f311e2265', 'hex')

  {
    const codec = Codec(key)

    t.equal(
      0,
      Buffer.compare(
        Buffer.from('41a7084876', 'hex'),
        codec.encode('hello')
      ),
      'encodes to expected value without nonce'
    )
  }

  {
    const nonce = Buffer.from('c2acac53ced5a443e192140e65d7b07cd6130137b731676a', 'hex')
    const codec = Codec(nonce, key)

    t.true(Buffer.isBuffer(codec.encode('hello')))
    t.equal(
      0,
      Buffer.compare(
        Buffer.from('289c3accba', 'hex'),
        codec.encode('hello')
      ),
      'encodes to expected value with nonce'
    )
  }

  t.end()
})

test('buffer = codec.decode(buffer[, offset])', (t) => {
  const nonce = crypto.randomBytes(24)
  const key = crypto.randomBytes(32)
  const codec = Codec(key, nonce)

  t.equal(
    0,
    Buffer.compare(
      Buffer.from('hello'),
      codec.decode(codec.encode('hello'))
    ),
    'decodes value from encoded value'
  )

  t.end()
})

test('codec = Codec(key, nonce, { valueEncoding })', (t) => {
  const { Message } = pbs('message Message { string data = 1; }')
  const nonce = crypto.randomBytes(24)
  const key = crypto.randomBytes(32)
  const codec = Codec(key, nonce, { valueEncoding: Message })
  t.deepEqual(
    { data: 'hello world' },
    codec.decode(codec.encode({ data: 'hello world' }))
  )
  t.end()
})
