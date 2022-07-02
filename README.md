### Intro

A Swift library that provides cryptographic authentication algorithms.

- HOTP: An HMAC-Based One-Time Password Algorithm https://www.rfc-editor.org/rfc/rfc4226
- OCRA: OATH Challenge-Response Algorithm https://www.rfc-editor.org/rfc/rfc6287.html 

### Setup

Available via SPM. Check out `Package.swift`.

### Usage

HOTP:

```
import AuthentiCode

let counter: UInt64 = // pass a counter value
let secret = "12345678901234567890".data(using: .utf8)!
let hotp = HOTP.generate(secret: secret, counter: UInt64(1))
print("HOTP: \(hotp)")

```


OCRA:

```
import AuthentiCode

let ocraSuite = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1"
let key = "3132333435363738393031323334353637383930313233343536373839303132"
let password = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220" // 1234 SHA1 hash value.
let sessionInformation = ""
let counter = ""
let timeStamp = ""
let question = "hello".hexString! // hex representation of a question. 
let ocra = OCRA.generate(ocraSuite: ocraSuite, key: key, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)
print("OCRA: \(ocra)")

```

Check out unit tests for further examples.

