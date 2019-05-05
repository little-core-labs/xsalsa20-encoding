xsalsa20-encoding
=================

XSalsa20 codec for encoding and decoding values into and from buffers and suitable

## Installation

```sh
$ npm install xsalsa20-encoding
```

## Usage

```js
const codec = require('xsalsa20-encoding')(nonce, secretKey)

// encode a value
buffer = codec.encode(value)

// decode a value
value = codec.decode(buffer)
```

## Example

```js
const crypto = require('crypto')
const Codec = require('xsalsa20-encoding')

const nonce = crypto.randomBytes(24)
const key = crypto.randomBytes(32)

const codec = Codec(nonce, key)
const hello = codec.encode('hello')
const world = codec.encode('world')

console.log('%s %s', codec.decode(hello), codec.decode(world)) // 'hello world'
```

## API

### `codec = require('xsalsa20-encoding')([nonce,] secretKey)`

Create a codec object from a 24 byte `nonce` and 32 byte `secretKey`. If
only a 32 byte `nonce` is given, it is treated as a `secretKey`.

```js
const nonce = crypto.randomBytes(24)
const key = crypto.randomBytes(32)
const codec = Codec(nonce, key)
```

or

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
const length = codec.encodingLength('hello world') // 11
```

## License

MIT
