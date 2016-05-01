var crypto = require('crypto')
var levelup = require('levelup')
var memdown = require('memdown')
var encryption = require('./')

var passwordBased = encryption({
  // key derivation parameters
  saltBytes: 32,
  digest: 'sha256',
  keyBytes: 32,
  // iterations for pbkdf2Sync used to derive the encryption key from the password
  iterations: 100000,
  // encryption parameters
  algorithm:'aes-256-cbc',
  ivBytes: 16,
  // tip: this password is crap
  password: 'oogabooga'
})

var dbPath = 'some.db'
var db = levelup(dbPath, {
  db: memdown,
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

    console.log('retrieved plaintext: ' + JSON.stringify(v)) // {"hey":ho"}

    // let's see the ciphertext stored:
    db.close(function () {
      var raw = rawDB(dbPath)

      raw.get(sha256(key), function (err, ciphertext) {
        if (err) throw err

        console.log('stored ciphertext (+ salt + iv): ' + ciphertext.toString('base64'))
      })
    })
  })
})

function sha256 (key) {
  return crypto.createHash('sha256')
    .update(key)
    .digest('base64')
}

function rawDB (path) {
  return levelup(path, {
    db: memdown,
    valueEncoding: 'binary'
  })
}
