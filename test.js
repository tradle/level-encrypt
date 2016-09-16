
var crypto = require('crypto')
var test = require('tape')
var levelup = require('levelup')
var memdown = require('memdown')
var updown = require('level-updown')
var series = require('run-series')
var encryption = require('./')
var DB_COUNTER = 0

test('encrypt/decrypt', function (t) {
  var passwordBased = {
    keyBytes: 32,
    saltBytes: 32,
    ivBytes: 16,
    digest: 'sha256',
    algorithm: 'aes-256-cbc',
    iterations: 10000,
    password: 'ooga'
  }

  var keyBased = {
    key: crypto.randomBytes(32)
  }

  var encryptors = [
    passwordBased,
    keyBased
  ]

  series(encryptors.map(function (encryptionOpts) {
    return function (cb) {
      var db = newDB()
      var encrypted = encryption.toEncrypted(db, encryptionOpts)
      var key = 'ho'
      var val = { hey: 'ho' }
      encrypted.put(key, val, function (err) {
        if (err) throw err

        encrypted.get(key, function (err, v) {
          if (err) throw err

          t.same(v, val)
          db.get(sha256(key), function (err, ciphertext) {
            if (err) throw err

            t.ok(ciphertext.length > 16 + 32) // at least bigger than iv + salt
            t.notSame(ciphertext, val)
            cb()
          })
        })
      })
    }
  }), function (err) {
    if (err) throw err

    t.end()
  })
})

test('open / close', function (t) {
  var dbPath = 'blah.db' + (DB_COUNTER++)
  var db = makeDB()

  var key = 'ho'
  var val = { hey: 'ho' }
  db.put(key, val, function (err) {
    if (err) throw err

    db.close(function () {
      db = makeDB()
      db.get(key, function (err, val1) {
        if (err) throw err

        t.same(val, val1)
        t.end()
      })
    })
  })

  function makeDB () {
    return encryption.toEncrypted(levelup(dbPath, {
      db: memdown,
      keyEncoding: 'binary'
    }), {
      password: 'ooga'
    })
  }
})

test('global vs per-item salt', function (t) {
  t.plan(6)

  var globalSalts = [
    null,
    crypto.randomBytes(32)
  ]

  globalSalts.forEach(function (globalSalt) {
    var dbPath = 'blah' + (DB_COUNTER++)
    var rawDB = levelup(dbPath, {
      keyEncoding: 'binary',
      db: memdown
    })

    var db = encryption.toEncrypted(rawDB, {
      salt: globalSalt,
      password: 'poop'
    })

    db.put('hey', 'ho', function (err) {
      if (err) throw err

      db.close(function () {
        var rawDB = levelup(dbPath, {
          db: memdown
        })

        rawDB.get('hey', function (err, val1) {
          t.ok(err)
        })

        rawDB.get(sha256('hey'), function (err, val1) {
          t.error(err)
          var unserialized = encryption._unserialize(val1)
          t.equal(unserialized.length, globalSalt ? 2 : 3)
        })
      })
    })
  })
})

test('basic', function (t) {
  var db = newDB()
  var encrypted = encryption.toEncrypted(db, {
    key: crypto.randomBytes(32)
  })

  var hashedKey
  var encryptedVal
  db.on('put', function (key, val) {
    hashedKey = key
    encryptedVal = val
  })

  encrypted.put('hey', 'ho', function (err) {
    if (err) throw err

    encrypted.get('hey', function (err, val) {
      if (err) throw err

      t.equals(val, 'ho')
      db.get('hey', function (err, val) {
        t.ok(err)
        db.get(hashedKey, function (err, val) {
          if (err) throw err

          t.same(val, encryptedVal)
          t.end()
        })
      })
    })
  })
})

test('stream', function (t) {
  var db = newDB()
  var encrypted = encryption.toEncrypted(db, {
    key: crypto.randomBytes(32)
  })

  encrypted.put('hey', 'ho', function (err) {
    if (err) throw err

    var data = []
    encrypted.createValueStream()
      .on('data', data.push.bind(data))
      .on('end', function () {
        t.same(data, ['ho'])
        t.end()
      })
  })
})

function newDB (opts) {
  opts = opts || {
    keyEncoding: 'binary',
    valueEncoding: 'binary'
  }

  opts.db = opts.db || memdown
  return levelup('blah' + (DB_COUNTER++), opts)
}

function sha256 (key) {
  return crypto.createHash('sha256').update(key).digest()
}
