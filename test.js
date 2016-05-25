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

// 1. KDF and SHA256 are different both hashing functions, but just different ones correct?


// Exploration of functions

var sha = SHA256('roneesh');
// console.log(sha);
// console.log(bitarray_len(sha))
// SHA256 always returns a NON-RANDOM 256-bit bitarray

var random = random_bitarray(128);
// console.log(random);
// console.log(bitarray_len(random));
// Returns a randdom bitarray of the % 32 lenghth you specify

var ba_str = string_to_bitarray('abcdefgh');
// console.log(ba_str);
// console.log(bitarray_len(ba_str));
// So every letter is an NON-RANDOM 8-bit bitarray, and they together
// form a bitarray of length 8 * characterCount

var kdf = KDF('testPassword', 'saltines');
// console.log(kdf);
// console.log(bitarray_len(kdf))
// KDF always returns a NONRANDOM 256-bit bitarray

var k0 = SHA256(kdf);
// console.log(k0);
// console.log(bitarray_len(k0))
// SHA256(KDF(pwd,salt)) returns a NONRANDOM 256-bit bitarray


// var fakeSalt = random_bitarray(128),
//     fakePwd = 'fakefake',
//     fakeKdf = KDF(fakePwd, fakeSalt)
//     KdfConcat0 = bitarray_concat(fakeKdf, 0),
//     KdfConcat1 = bitarray_concat(fakeKdf, 1);
// console.log(bitarray_len(SHA256(fakeKdf)));
// console.log(SHA256(fakeKdf));
// console.log(bitarray_len(SHA256(KdfConcat0)));
// console.log(SHA256(KdfConcat0));
// console.log(bitarray_len(SHA256(KdfConcat1)));
// console.log(SHA256(KdfConcat1));



// var passwordManager = {
//     salt: null,
//     HMACkey: null, //128-bit key from 256
//     AESkey: null, //128-bit key rom 256
//     setup_cipher: null,
//     passwords : {
//         //'hashedDomainName' : {
//         //    salt: 'salt',
//         //    encryptedPassword: 'pwd'
//         //}
//         // but I ended up using...
//         // 'HMAChashedDomainName' : 'aesEncryptedPassword'
//     },
// };

// var managerPassword = 'test123';
// var domainName = 'google.com';
// var domainPassword = 'google123';

// // 1. Get the key from the password
// passwordManager['salt'] = random_bitarray(128);

// // concat KDF with 0, and 1 and then SHA it to get 256, then slice it to get a 128-bit key
// passwordManager['AESkey'] = bitarray_slice(SHA256(bitarray_concat(KDF(managerPassword, passwordManager['salt']), 0)), 0, 128);
// passwordManager['HMACkey'] = bitarray_slice(SHA256(bitarray_concat(KDF(managerPassword, passwordManager['salt']), 1)), 0, 128);
// passwordManager['setup_cipher'] = setup_cipher(passwordManager['AESkey']);

// console.log(passwordManager);
// console.log('\n');

// // 2. Hash the Domain you want to save, for now it's value is plaintext
// var hashedDomain = HMAC(passwordManager['HMACkey'], domainName);
// passwordManager['passwords'][hashedDomain] = {}

// // console.log(passwordManager);
// // console.log('\n');

// // 3. Encrypt the password
// var encryptedDomainPassword = enc_gcm(passwordManager['setup_cipher'], string_to_bitarray(domainPassword));
// passwordManager['passwords'][hashedDomain] = encryptedDomainPassword;

// // console.log(passwordManager);
// // console.log('\n');

// // 4. Write a function to get a key/value in passwords

// function getPassword(domain) {
//     hashOfDomain = HMAC(passwordManager['HMACkey'], domain);
//     if (passwordManager['passwords'][hashOfDomain]) {            
//         var plainTextPassword = bitarray_to_string(dec_gcm(passwordManager['setup_cipher'], passwordManager['passwords'][hashOfDomain]));
//         // console.log(domain + ' : ' + plainTextPassword);
//     } else { 
//         // console.log(domain + ' : this pwd is not in your DB!'); 
//     }
// }

// // getPassword('google.com');
// // getPassword('facebook.com');

// // 5. Abstract steps 2 and 3 into a function
// function addPassword(domain, password) {
//     var hashedDomain = HMAC(passwordManager['HMACkey'], domain);
//     passwordManager['passwords'][hashedDomain] = {}

//     var encryptedDomainPassword = enc_gcm(passwordManager['setup_cipher'], string_to_bitarray(password));
//     passwordManager['passwords'][hashedDomain] = encryptedDomainPassword;
// }
// // addPassword('linkedin.com', '123Linked!');
// // getPassword('linkedin.com');



// // 6. Write a function to save the passwordManager as JSON

// function saveAsJSON(passwordManager) {
//     return JSON.stringify(passwordManager);
// }