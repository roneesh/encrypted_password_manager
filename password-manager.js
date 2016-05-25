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
    priv.data.version = "CS 255 Password Manager v1.0";
    priv.data.salt = random_bitarray(128);
    priv.secrets.AESkey = bitarray_slice(SHA256(bitarray_concat(KDF(password, priv.data.salt), 0)), 0, 128);
    priv.secrets.HMACkey = bitarray_slice(SHA256(bitarray_concat(KDF(password, priv.data.salt), 1)), 0, 128);
    priv.data.setup_cipher = setup_cipher(priv.secrets.AESkey);
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
      
      // 1. Read the JSON string of the priv obj we saved
      var suppliedData = JSON.parse(repr);
      var suppliedChecksum = checksum;

      // // 2. If the supplied Checksum is not equal to SHA256(suppliedData), then we know data is tampered, so reject
      // if (SHA256(suppliedData) !== suppliedChecksum) {
      //   throw 'Data was tampered with!';
      // }
      // console.log('suppliedData\n')
      // console.log(suppliedData);
      // console.log('\n')

      // // 3. Once we're sure data is good via checksum, we can check if password is correct, by comparing to AESkey. Should we compare to HMAC too??
      var passwordHash = bitarray_slice(SHA256(bitarray_concat(KDF(password, suppliedData.data['salt']), 0)), 0, 128);

      // console.log(
      //   'is passwordHash equal to suppliedData.secrets.AESkey?',
      //   bitarray_equal(passwordHash, suppliedData.secrets.AESkey)
      // );

      if (bitarray_equal(passwordHash, suppliedData.secrets.AESkey)) {
        // console.log('bitArrays are equal')
        //3a. If pwd is equal to AESkey, then set it to priv and make ready true
        priv = suppliedData;
        ready = true;
        return true;
      } else {

        //3b. Else throw that password is wrong
        return false;
      }
  }

  keychain.display = function() {
    return priv;
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
    var dump = [ JSON.stringify(priv), SHA256(priv) ];
    return dump;
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

    console.log('.get priv.secrets', '\n', priv.secrets)
    var hashOfDomain = HMAC(priv.secrets.HMACkey, name);
    console.log('.get hashOfDomain: ', hashOfDomain);

    if (priv.secrets[hashOfDomain]) {            
        var plainTextPassword = bitarray_to_string(dec_gcm(priv.data.setup_cipher, priv.secrets[hashOfDomain]));
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

    var hashedDomain = HMAC(priv.secrets.HMACkey, name);
    var encryptedDomainPassword = enc_gcm(priv.data.setup_cipher, string_to_bitarray(value));
    
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
    
    var hashOfDomain = HMAC(priv.secrets.HMACkey, name);
    
    if (priv.secrets[hashOfDomain]) {            
        delete priv.secrets[hashOfDomain];
        return true;
    } else { 
        return false
    }
  }

  return keychain;
}

module.exports.keychain = keychain;
