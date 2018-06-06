
var Buffer = require('buffer').Buffer
var crypto = require('crypto')
var hydration = require('hydration')
var levelup = require('levelup')
var updown = require('level-updown')

// opts from SQLCipher: https://www.zetetic.net/sqlcipher/design/
var DEFAULT_PASSWORD_BASED_OPTS = {
  // key derivation parameters
  password: null,
  saltBytes: 32,
  salt: null,
  digest: 'sha256',
  keyBytes: 32,
  iterations: 64000,
  // encryption parameters
  algorithm:'aes-256-cbc',
  ivBytes: 16,
}

var DEFAULT_KEY_BASED_OPTS = {
  algorithm:'aes-256-cbc',
  ivBytes: 16,
  key: null
}

exports.encrypt = encrypt
exports.decrypt = decrypt
exports.hydration = hydration
exports.dehydrate = dehydrate
exports.hydrate = hydrate
exports.toEncrypted = toEncryptedLevelup
exports.keyHashFunction = sha256
exports._unserialize = unserialize // for testing

function toEncryptedLevelup (db, opts) {
  var kEncoding = db.options.keyEncoding
  if (kEncoding !== 'binary') {
    throw new Error('expected "binary" keyEncoding')
  }

  var vEncoding = db.options.valueEncoding
  if (vEncoding !== 'binary' && vEncoding !== 'utf8') {
    throw new Error('expected "binary" or "utf8" valueEncoding')
  }

  opts = opts || {}
  if (!opts.encrypt || !opts.decrypt) {
    opts = normalizeOpts(opts)
  }

  var encryptValue = opts.encrypt || function (data) {
    return encrypt(data, opts)
  }

  var decryptValue = opts.decrypt || function (data) {
    return decrypt(data, opts)
  }

  var rawHashKey = opts.keyHashFunction || exports.keyHashFunction
  return levelup({
    keyEncoding: db.options.keyEncoding,
    valueEncoding: {
      encode: dehydrate,
      decode: function identity (val) {
        return val
      }
    },
    db: function () {
      var ud = updown(db)
      ud.extendWith({
        preGet: preHashKey,
        postGet: postGet,
        postIterator: postIterator,
        preDel: preHashKey,
        prePut: prePut,
        preBatch: preBatch
      })

      return ud
    }
  })

  function hashKey (key) {
    var hash = rawHashKey(key)
    if (!Buffer.isBuffer(hash)) hash = new Buffer(hash)

    return hash
  }

  function postIterator (iterator) {
    iterator.extendWith({
      postNext: postNext
    })

    return iterator
  }

  function postNext (err, key, value, callback, next) {
    if (!err && value) value = hydrate(decryptValue(value))

    next(err, key, value, callback)
  }

  function preHashKey(key, options, callback, next) {
    key = hashKey(key)
    next(key, options, callback)
  }

  function postGet (key, options, err, value, callback, next) {
    if (!err) {
      try {
        value = hydrate(decryptValue(value))
      } catch (e) {
        err = e
      }
    }

    next(key, options, err, value, callback)
  }

  function prePut (key, value, options, callback, next) {
    key = hashKey(key)
    value = encryptValue(value)
    next(key, value, options, callback)
  }

  function preBatch (array, options, callback, next) {
    for (var i = 0; i < array.length; i++) {
      var row = array[i]
      row.key = hashKey(row.key)
      if (row.type == 'put') {
        row.value = encryptValue(row.value)
      }
    }

    next(array, options, callback)
  }
}

function encrypt (data, opts) {
  var salt = !opts.key && (opts.salt || crypto.randomBytes(opts.saltBytes))
  var key = opts.key || crypto.pbkdf2Sync(opts.password, salt, opts.iterations, opts.keyBytes, opts.digest)
  var iv = opts.iv || crypto.randomBytes(opts.ivBytes)
  var cipher = crypto.createCipheriv(opts.algorithm, key, iv)
  var ciphertext = Buffer.concat([cipher.update(data), cipher.final()])
  var parts = [
    iv,
    ciphertext
  ]

  if (salt) parts.push(salt)

  return serialize(parts)
}

function decrypt (data, opts) {
  var parts = unserialize(data)
  var iv = parts[0]
  var ciphertext = parts[1]
  var salt = parts[2]
  var key = opts.key
  if (!key) {
    key = crypto.pbkdf2Sync(opts.password, salt, opts.iterations, opts.keyBytes, opts.digest)
  }

  var decipher = crypto.createDecipheriv(opts.algorithm, key, iv)
  var m = decipher.update(parts[1])
  data = Buffer.concat([m, decipher.final()]).toString()
  return JSON.parse(data)
}

function hydrate (entity) {
  return hydration.hydrate(entity)
}

function dehydrate (entity) {
  // if (Buffer.isBuffer(entity)) return entity
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

function sha256 (key) {
  return crypto.createHash('sha256').update(key).digest()
}

function normalizeOpts (_opts) {
  var opts = {}
  var defaults = _opts.key ? DEFAULT_KEY_BASED_OPTS : DEFAULT_PASSWORD_BASED_OPTS
  for (var p in defaults) {
    opts[p] = p in _opts ? _opts[p] : defaults[p]
  }

  assert(typeof opts.algorithm === 'string', 'Expected string "algorithm"')
  assert(typeof opts.ivBytes === 'number', 'Expected number "ivBytes"')

  if (!opts.key) {
    assert(typeof opts.keyBytes === 'number', 'Expected number "keyBytes"')
    assert(typeof opts.iterations === 'number', 'Expected number "iterations"')
    assert(typeof opts.password === 'string' || Buffer.isBuffer(opts.password), 'Expected string or Buffer "password"')
    assert(typeof opts.digest === 'string', 'Expected string "digest"')

    if (opts.salt) {
      assert(Buffer.isBuffer(opts.salt), 'Expected Buffer "salt"')
      // if global salt is provided don't recalculate key every time
      if (!opts.key) {
        opts.key = crypto.pbkdf2Sync(opts.password, opts.salt, opts.iterations, opts.keyBytes, opts.digest)
      }
    } else {
      assert(typeof opts.saltBytes === 'number', 'Expected number "saltBytes"')
    }
  }

  return opts
}
