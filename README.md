# level-encrypt

*Note: bulk of code originates from [modeler-leveldb](https://github.com/carlos8f/modeler-leveldb).*

Encryption for levelup. Performs necessary hydration/dehydration of JSON objects using [hydration](https://github.com/carlos8f/hydration).

# Usage

```js
var crypto = require('crypto')
var levelup = require('levelup')
var memdown = require('memdown')
var encryption = require('level-encrypt')

var encryptionOptions = {
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
  // optionally, pass in key instead of password
  // key: myKeyBuffer
}

// for custom encryption options, encryptionOptions should look like this:
// {
//   encrypt: Function,
//   decrypt: Function
// }
// 

var dbPath = './encrypted.db'
var baseDB = levelup(dbPath, {
  db: memdown
})

var db = encryption.toEncrypted(baseDB, encryptionOptions)
var key = 'ho'
var val = { hey: 'ho' }
db.put(key, val, function (err) {
  if (err) throw err

  db.get(key, function (err, v) {
    if (err) throw err

    console.log('retrieved plaintext: ' + JSON.stringify(v)) // {"hey":ho"}

    // let's see the ciphertext stored:
    db.close(function () {
      baseDB.get(encryption.keyHashFunction(key), function (err, ciphertext) {
        if (err) throw err

        console.log('stored ciphertext (+ salt + iv): ' + ciphertext.toString('base64'))
      })
    })
  })
})
```
