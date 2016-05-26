"use strict";

var lib = require("./lib"),
    bitarray_equal = lib.bitarray_equal;

function assert(condition, message) {
  if (!condition) {
    console.trace();
    throw message || "Assertion failed!";
  }
}

var password_manager = require("./password-manager");

var password = "password123!!";
var keychain = password_manager.keychain();

console.log("Initializing a toy password store");
keychain.init(password);

var kvs = { "service1": "value1", 
            "service2": "value2",
            "service3": "value3" };

console.log("Adding keys to password manager");
for (var k in kvs) {
  keychain.set(k, kvs[k]);
}

console.log("Testing get");
for (var k in kvs) {
  assert(keychain.get(k) === kvs[k], ("Get failed for key " + k));
}
assert(keychain.get("service4") === null);

console.log("Testing remove");
assert(keychain.remove("service1"));
assert(!keychain.remove("service4"));
assert(keychain.get("service4") === null);

console.log("Saving database:");
var data = keychain.dump();

var contents = data[0];
var cksum = data[1];

// console.log(contents);

console.log("Loading database");
var new_keychain = password_manager.keychain();
new_keychain.load(password, contents, cksum);

console.log('\nold keychain:');
console.log(keychain.display());
console.log('\nnew keychain:');
console.log(new_keychain.display());

console.log('\nare the ciphers of both keychains equal?');
console.log(keychain.cipher === new_keychain.cipher);

console.log('are the hmac keys of both keychains equal?');
console.log(bitarray_equal(keychain.hmac, new_keychain.hmac));

console.log('are the aes keys of both keychains equal?');
console.log(bitarray_equal(keychain.aes, new_keychain.aes));

console.log('are the salts of both keychains equal?');
console.log(bitarray_equal(keychain.salt, new_keychain.salt));

console.log("\nChecking contents of new database");
for (var k in kvs) {
  assert(keychain.get(k) === new_keychain.get(k));
}

// new_keychain.get is failing! dec_gcm is the culprit! What is wrong!??
console.log(new_keychain.get('service2'));

console.log("All tests passed!");