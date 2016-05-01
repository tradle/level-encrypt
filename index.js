
var Buffer = require('buffer').Buffer
var crypto = require('crypto')
var hydration = require('hydration')

exports = module.exports = passwordBased
exports.custom = custom

function custom (opts) {
  assert(typeof opts.encrypt === 'function', 'Expected function "encrypt"')
  assert(typeof opts.decrypt === 'function', 'Expected function "decrypt"')

  var encrypt = opts.encrypt
  var decrypt = opts.decrypt
  return {
    encrypt: dehydrateAndEncrypt,
    decrypt: decryptAndHydrate,
    valueEncoding: {
      encode: dehydrateAndEncrypt,
      decode: decryptAndHydrate,
      buffer: true,
      name: 'encryption'
    }
  }

  function dehydrateAndEncrypt (entity, cb) {
    var data = hydration.dehydrate(entity)
    data = new Buffer(JSON.stringify(data))

    if (cb) {
      encrypt(data, onEncrypted)
    } else {
      return onEncrypted(null, encrypt(data))
    }

    function onEncrypted (err, ciphertext) {
      if (cb) {
        cb(err, ciphertext)
      } else {
        return ciphertext
      }
    }
  }

  function decryptAndHydrate (data, cb) {
    if (cb) {
      decrypt(data, onDecrypted)
    } else {
      return onDecrypted(null, decrypt(data))
    }

    function onDecrypted (err, plaintext) {
      if (cb) {
        cb(err, plaintext)
      } else {
        return hydration.hydrate(plaintext)
      }
    }
  }
}

function passwordBased (opts) {
  assert(typeof opts.saltBytes === 'number', 'Expected number "saltBytes"')
  assert(typeof opts.keyBytes === 'number', 'Expected number "keyBytes"')
  assert(typeof opts.iterations === 'number', 'Expected number "iterations"')
  assert(typeof opts.password === 'string' || Buffer.isBuffer(opts.password), 'Expected string or Buffer "password"')
  assert(typeof opts.algorithm === 'string', 'Expected string "algorithm"')
  assert(typeof opts.digest === 'string', 'Expected string "digest"')

  return custom({
    encrypt: function (data) {
      return encrypt(data, opts)
    },
    decrypt: function (data) {
      return decrypt(data, opts)
    }
  })
}

function encrypt (data, opts) {
  var salt = crypto.randomBytes(opts.saltBytes)
  var iv = crypto.randomBytes(opts.ivBytes)
  var key = crypto.pbkdf2Sync(opts.password, salt, opts.iterations, opts.keyBytes, opts.digest)
  var cipher = crypto.createCipheriv(opts.algorithm, key, iv)
  var ciphertext = Buffer.concat([cipher.update(data), cipher.final()])
  var parts = [
    salt,
    iv,
    ciphertext
  ]

  return serialize(parts)
}

// string to entity
function decrypt (data, opts) {
  var parts = unserialize(data)
  var salt = parts[0]
  var iv = parts[1]
  var ciphertext = parts[2]
  var key = crypto.pbkdf2Sync(opts.password, salt, opts.iterations, opts.keyBytes, opts.digest)
  var decipher = crypto.createDecipheriv(opts.algorithm, key, iv)
  var m = decipher.update(parts[2])
  data = Buffer.concat([m, decipher.final()]).toString()
  return JSON.parse(data)
}

function serialize (buffers) {
  var parts = [], idx = 0
  buffers.forEach(function (part) {
    var len = Buffer(4)
    if (typeof part === 'string') part = Buffer(part)
    len.writeUInt32BE(part.length, 0)
    parts.push(len)
    idx += len.length
    parts.push(part)
    idx += part.length
  })

  return Buffer.concat(parts)
}

function unserialize (buf) {
  var parts = []
  var l = buf.length, idx = 0
  while (idx < l) {
    var dlen = buf.readUInt32BE(idx)
    idx += 4
    var start = idx
    var end = start + dlen
    var part = buf.slice(start, end)
    parts.push(part)
    idx += part.length
  }

  return parts
}

function assert (statement, errMsg) {
  if (!statement) throw new Error(errMsg || 'Assertion failed')
}
