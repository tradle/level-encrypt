
var Buffer = require('buffer').Buffer
var crypto = require('crypto')
var hydration = require('hydration')

// opts from SQLCipher: https://www.zetetic.net/sqlcipher/design/
var DEFAULT_OPTS = {
  // key derivation parameters
  saltBytes: 32,
  digest: 'sha256',
  keyBytes: 32,
  iterations: 64000,
  // encryption parameters
  algorithm:'aes-256-cbc',
  ivBytes: 16,
  password: null
}

exports = module.exports = passwordBased
exports.custom = custom
exports.encrypt = encrypt
exports.decrypt = decrypt
exports.dehydrate = dehydrate
exports.hydrate = hydrate

function custom (opts) {
  assert(typeof opts.encrypt === 'function', 'Expected function "encrypt"')
  assert(typeof opts.decrypt === 'function', 'Expected function "decrypt"')

  var encrypt = opts.encrypt
  var decrypt = opts.decrypt
  return {
    encrypt: dehydrateAndEncrypt,
    decrypt: decryptAndHydrate,
    // pass in to levelup
    valueEncoding: {
      encode: dehydrateAndEncrypt,
      decode: decryptAndHydrate,
      buffer: true,
      name: 'encryption'
    }
  }

  function dehydrateAndEncrypt (entity, cb) {
    var data = dehydrate(entity)
    if (cb) {
      encrypt(data, onEncrypted)
    } else {
      return onEncrypted(null, encrypt(data))
    }

    function onEncrypted (err, ciphertext) {
      return maybeAsync(err, ciphertext, cb)
    }
  }

  function decryptAndHydrate (data, cb) {
    if (cb) {
      decrypt(data, onDecrypted)
    } else {
      return onDecrypted(null, decrypt(data))
    }

    function onDecrypted (err, plaintext) {
      return maybeAsync(err, err ? null : hydrate(plaintext), cb)
    }
  }
}

function passwordBased (_opts) {
  var opts = {}
  for (var p in DEFAULT_OPTS) {
    opts[p] = p in _opts ? _opts[p] : DEFAULT_OPTS[p]
  }

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
  var salt = opts.salt || crypto.randomBytes(opts.saltBytes)
  var iv = opts.iv || crypto.randomBytes(opts.ivBytes)
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

function hydrate (entity) {
  return hydration.hydrate(entity)
}

function dehydrate (entity) {
  var data = hydration.dehydrate(entity)
  return new Buffer(JSON.stringify(data))
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

function maybeAsync (err, val, cb) {
  if (cb) {
    cb(err, val)
  } else {
    return val
  }
}
