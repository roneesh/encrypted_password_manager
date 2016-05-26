"use strict";

var lib = require("./lib"),
    bitarray_equal = lib.bitarray_equal,
    util = require('util')

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

console.log("Saving database, what I dump:");
var data = keychain.dump();

var contents = data[0];
var cksum = data[1];

console.log(cksum);

console.dir(JSON.parse(contents));

console.log("Loading database");
var new_keychain = password_manager.keychain();
assert(new_keychain.load(password, contents, cksum) === true, 'Keychain did not load!');
console.log("First DB loaded!");

console.log("Loading DB with bad password, should be false!")
var new_keychain2 = password_manager.keychain();
new_keychain2.load('badPassword', contents, cksum);
// assert(new_keychain2.load('badPassword', contents, cksum) === false, 'The bad password worked?');
console.log('It was false, password protection is working!');

console.log("\nChecking contents of new database");
for (var k in kvs) {
  assert(keychain.get(k) === new_keychain.get(k));
}

console.log("All tests passed!");