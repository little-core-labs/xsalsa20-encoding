const crypto = require('crypto')
const Codec = require('./')

const nonce = crypto.randomBytes(24)
const key = crypto.randomBytes(32)

const codec = Codec(nonce, key)
const hello = codec.encode('hello')
const world = codec.encode('world')

console.log('%s %s', codec.decode(hello), codec.decode(world)) // 'hello world'
