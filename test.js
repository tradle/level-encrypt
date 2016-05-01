
var crypto = require('crypto')
var test = require('tape')
var levelup = require('levelup')
var memdown = require('memdown')
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

  var db = newDB({
    // you might want to at least hash keys
    keyEncoding: {
      encode: sha256
    },
    valueEncoding: passwordBased.valueEncoding
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
          t.end()
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
