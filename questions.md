# The relationship between a plain-text 'password' and a key

5. So we need two keys, HMAC and AES, because each one requires a key to do our encryption, does it matter how we get the key from our plain-text 'passowrd'? Is pretty much any crytpographic hashing method ok?

4. Is the only reason we don't use the same key for HMAC and AES because it's less secure, e.g. if your single key is compromised both your HMAC and AES data is exposed?

3. Couldn't we just develop a 129-bit key then, and then use bits 0-128 for HMAC and 1-129 for AES? Do we just avoid that due to overlap? Also I guess bits are easy to

2. Is this a proper implementation of K || 0, K || 1, etc?
passwordManager['AESkey'] = bitarray_slice(SHA256(bitarray_concat(KDF(managerPassword, passwordManager['salt']), 0)), 0, 128);

1. What in JSON.stringify could change the data so decrypting would fail? My checksum in the keychain.load is failing, does that indicate that the JSON.parse is not returning the data to its original state?

0. Why is my checksum in keychain.load failing? 