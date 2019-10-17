xsalsa20-encoding
=================

> XSalsa20 codec that implements that [abstract-encoding][abstract-encoding] interface.
> Nonces are generated randomly and prepended to the ciphertext.

## Installation

```sh
$ npm install xsalsa20-encoding
```

## Usage

```js
const codec = require('xsalsa20-encoding')(secretKey)

// encode a value
buffer = codec.encode(value)

// decode a value
value = codec.decode(buffer)
```

## Example

```js
const crypto = require('crypto')
const Codec = require('xsalsa20-encoding')

const key = crypto.randomBytes(32)

const codec = Codec(key)
const hello = codec.encode('hello')
const world = codec.encode('world')

console.log('%s %s', codec.decode(hello), codec.decode(world)) // 'hello world'
```

### Custom Value Encodings

```js
const pbs = require('protocol-buffers')
const { Message } = pbs(`
message {
  string data = 1;
}
`)

const codec = Codec(key, { valueEncoding: Message })
const encoded = codec.encode({ data: 'hello world' })
const message = codec.decode(encoded) // { data: 'hello world' }
```

## API

### `codec = require('xsalsa20-encoding')([secretKey[, opts])`

Create a codec object from 32 byte `secretKey`.

```js
const key = crypto.randomBytes(32)
const codec = Codec(key)
```

#### `buffer = codec.encode(value[, output[, offset]])`

Encode a value using [xsalsa20](https://github.com/mafintosh/xsalsa20)
(XOR) into an optional `output` buffer at an optional `offset`
defaulting to `0`. If an `output` buffer is not given, one is allocated
for you and returned.

```js
const buffer = codec.encode('hello world')
```

#### `value = codec.decode(buffer[, offset])`

Decode a buffer using [xsalsa20](https://github.com/mafintosh/xsalsa20)
(XOR) at an optional `offset` defaulting to `0`.

```js
const value = codec.decode(buffer)
```

#### `length = codec.encodingLength(value)`

Returns the encoding length for a given `value`.

```js
const length = codec.encodingLength('hello world') // 35
```

## License

MIT


[abstract-encoding]: https://github.com/mafintosh/abstract-encoding
