
var crypto = require('crypto')
var test = require('tape')
var levelup = require('levelup')
var memdown = require('memdown')
var series = require('run-series')
var encryption = require('./')
var DB_COUNTER = 0

test('encrypt/decrypt', function (t) {
  var passwordBased = encryption({
    keyBytes: 32,
    saltBytes: 32,
    ivBytes: 16,
    digest: 'sha256',
    algorithm: 'aes-256-cbc',
    iterations: 100000,
    password: 'ooga'
  })

  var keyBased = encryption({
    key: crypto.randomBytes(32),
    salt: crypto.randomBytes(32)
  })

  var encryptors = [
    passwordBased,
    keyBased
  ]

  series(encryptors.map(function (encryptor) {
    return function (cb) {
      var db = newDB({
        // you might want to at least hash keys
        keyEncoding: {
          encode: sha256
        },
        valueEncoding: encryptor.valueEncoding
      })

      var key = 'ho'
      var val = { hey: 'ho' }
      db.put(key, val, function (err) {
        if (err) throw err

        db.get(key, function (err, v) {
          if (err) throw err

          t.same(v, val)

          db.close(function () {
            db = levelup(db.location, {
              db: memdown,
              valueEncoding: 'binary'
            })

            db.get(sha256(key), function (err, ciphertext) {
              if (err) throw err

              t.ok(ciphertext.length > 16 + 32) // at least bigger than iv + salt
              t.notSame(ciphertext, val)
              cb()
            })
          })
        })
      })
    }
  }), function (err) {
    t.error(err)
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
    var passwordBased = encryption({
      password: 'ooga'
    })

    return levelup(dbPath, {
      db: memdown,
      keyEncoding: {
        encode: sha256
      },
      valueEncoding: passwordBased.valueEncoding
    })
  }
})

test('global vs per-item salt', function (t) {
  t.plan(2)

  var globalSalts = [
    null,
    crypto.randomBytes(32)
  ]

  globalSalts.forEach(function (globalSalt) {
    var dbPath = 'blah' + (DB_COUNTER++)
    var passwordBased = encryption({
      salt: globalSalt,
      password: 'poop'
    })

    var db = levelup(dbPath, {
      db: memdown,
      valueEncoding: passwordBased.valueEncoding
    })

    db.put('hey', 'ho', function (err) {
      if (err) throw err

      db.put('yo', 'yo', function (err) {
        if (err) throw err

        db.close(function () {
          var rawDB = levelup(dbPath, {
            db: memdown
          })

          rawDB.get('hey', function (err, val1) {
            if (err) throw err

            rawDB.get('yo', function (err, val2) {
              if (err) throw err

              var salt1 = encryption._unserialize(val1)[0]
              var salt2 = encryption._unserialize(val2)[0]
              if (globalSalt) {
                t.same(salt1, salt2)
              } else {
                t.notSame(salt1, salt2)
              }
            })
          })
        })
      })
    })
  })
})

function newDB (opts) {
  opts = opts || {}
  opts.db = opts.db || memdown
  return levelup('blah' + (DB_COUNTER++), opts)
}

function sha256 (key) {
  return crypto.createHash('sha256')
    .update(key)
    .digest('base64')
}
