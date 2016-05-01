# level-encrypt

*Note: bulk of code originates from [modeler-leveldb](https://github.com/carlos8f/modeler-leveldb).*

Encryption for levelup. Use raw encrypt/decrypt functions or pass in to a levelup as `valueEncoding`. Performs necessary hydration/dehydration of JSON objects using [hydration](https://github.com/carlos8f/hydration).

# Usage

## Pass in as `valueEncoding`

```js
var crypto = require('crypto')
var levelup = require('levelup')
var memdown = require('memdown')
var encryption = require('level-encrypt')

var passwordBased = encryption({
  keyBytes: 32,
  saltBytes: 32,
  ivBytes: 16,
  digest: 'sha256',
  algorithm: 'aes-256-cbc',
  // iterations for pbkdf2Sync used to derive the encryption key from the password
  iterations: 100000,
  // yes, this one's taken, move along
  password: 'oogabooga'
})

var dbPath = 'some.db'
var db = encryptedDB(dbPath)
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

function encryptedDB (path) {
  return levelup(path, {
    db: memdown,
    // you might want to at least hash keys
    keyEncoding: {
      encode: sha256
    },
    valueEncoding: passwordBased.valueEncoding
  })
}

function rawDB (path) {
  return levelup(path, {
    db: memdown,
    valueEncoding: 'binary'
  })
}
```

## Raw, password-based

```js
var crypto = require('crypto')
var levelup = require('levelup')
var memdown = require('memdown')
var encryption = require('level-encrypt')

var passwordBased = encryption({
  keyBytes: 32,
  saltBytes: 32,
  ivBytes: 16,
  digest: 'sha256',
  algorithm: 'aes-256-cbc',
  // iterations for pbkdf2Sync used to derive the encryption key from the password
  iterations: 100000,
  // yes, this one's taken, move along
  password: 'oogabooga'
})

var ciphertext = passwordBased.encrypt({ 'something': 'else' })
var plaintext = passwordBased.decrypt(ciphertext)
console.log('decrypted: ' + JSON.stringify(plaintext))
```

## Specify your own encrypt/decrypt

```js
var encryption = require('level-encrypt')
var passwordBased = encryption.custom({
  encrypt: function (data) {
    // encrypt "data" your own way
    return data
  },
  decrypt: function (data) {
    // encrypt "data" your own way
    return data
  }
})

// continue as above
```
