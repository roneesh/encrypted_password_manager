"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
  // Class-private instance variables.
  var priv = {
    secrets: { /* Your secrets here */ },
    data: { /* Non-secret data here */ }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    priv.data.version = "Roneesh\'s Rad Passwords";
    priv.data.salt = random_bitarray(128);
    
    //concatenating 0 onto KDF output via bitarray_concat
    priv.data.AESkey = bitarray_slice(SHA256(bitarray_concat(KDF(password, priv.data.salt), 0)), 0, 128);
    priv.data.HMACkey = bitarray_slice(SHA256(bitarray_concat(KDF(password, priv.data.salt), 1)), 0, 128);
    priv.data.setup_cipher = setup_cipher(priv.data.AESkey);
    priv.data.passwordCheck = bitarray_to_base64(enc_gcm(priv.data.setup_cipher, string_to_bitarray('test')));
    ready = true;
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trusted_data_check
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (e.g., the result of a 
    * call to the save function). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trusted_data_check: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, checksum) {
      
      var cksumOfRepr = bitarray_to_base64(SHA256(string_to_bitarray(repr)))

      if (cksumOfRepr === checksum) {
        console.log('Data is good!');
      } else {
        console.log('Data is bad!');
      }
      // 1. Read the JSON string of the priv obj we saved
      var suppliedData = JSON.parse(repr);
      var suppliedChecksum = checksum;
      
      suppliedData.data.AESkey = bitarray_slice(SHA256(bitarray_concat(KDF(password, suppliedData.data.salt), 0)), 0, 128);
      suppliedData.data.HMACkey = bitarray_slice(SHA256(bitarray_concat(KDF(password, suppliedData.data.salt), 1)), 0, 128);
      suppliedData.data.setup_cipher = setup_cipher(suppliedData.data.AESkey);

      // // 2. If the supplied Checksum is not equal to SHA256(suppliedData), then we know data is tampered, so reject

      // // 3. Once we're sure data is good via checksum, we can check if password is correct by comparing to some other word.
      try {
        var passwordCheck = bitarray_to_string(dec_gcm(suppliedData.data.setup_cipher, base64_to_bitarray(suppliedData.data.passwordCheck)));
      } catch(e) {
        return false;
      }

      if (passwordCheck === 'test') {
        //3a. If pwd is equal to AESkey, then set it to priv and make ready true
        priv = suppliedData;
        ready = true;
        return true;
      
      } else {

        //3b. Else throw that password is wrong
        return false;
      }
  }

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  keychain.dump = function() {
    if (ready === false) {
      return null;
    }
    var preppedDump = JSON.parse(JSON.stringify(priv));
    delete preppedDump.data.AESkey;
    delete preppedDump.data.HMACkey;
    delete preppedDump.data.setup_cipher;
    
    return [ JSON.stringify(preppedDump), bitarray_to_base64(SHA256(string_to_bitarray(JSON.stringify(preppedDump)))) ];
    
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    if (ready === false) throw "Manager not ready";

    // 1. hash the domain we want to check for    
    var hashOfDomain = bitarray_to_base64(HMAC(priv.data.HMACkey, name));
    
    // 2. If that domain is in priv.secrets then decrypt the value of priv.secrets.hashOfDomain    
    if (priv.secrets[hashOfDomain]) {    
        // This line is breaking for new_keychain.get()!!! possibly because of corrupted data
        var plainTextPassword = bitarray_to_string(dec_gcm(priv.data.setup_cipher, base64_to_bitarray(priv.secrets[hashOfDomain])));
        return plainTextPassword;
    } else { 
        return null;
    }
  }

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {

    var hashedDomain = bitarray_to_base64(HMAC(priv.data.HMACkey, name));
    var encryptedDomainPassword = bitarray_to_base64(enc_gcm(priv.data.setup_cipher, string_to_bitarray(value)));
    
    priv.secrets[hashedDomain] = encryptedDomainPassword;

    return undefined;
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
    if (ready === false) { throw "Manager not ready"; }
    
    var hashOfDomain = bitarray_to_base64(HMAC(priv.data.HMACkey, name));
    
    if (priv.secrets[hashOfDomain]) {            
        delete priv.secrets[hashOfDomain];
        return true;
    } else { 
        return false
    }
  }

  keychain.display = function() {
    return priv;
  }
  keychain.cipher = function() {
    return priv.data.setup_cipher;
  }
  keychain.hmac = function() {
    return priv.data.HMACkey;
  }
  keychain.aes = function() {
    return priv.data.AESkey;
  }
  keychain.salt = function() {
    return priv.data.salt;
  }

  return keychain;
}

module.exports.keychain = keychain;
