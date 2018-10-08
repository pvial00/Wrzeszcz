# Wrzeszcz Cipher
Ultra High Speed Stream Cipher

*** Warning this cipher has not undergone serious cryptanalysis and should not be used in production systems.

Key sizes - 128, 256, 512, 1024, 2048 bit

A BlueDye derivative cipher.  After a modified keysetup is run, the key expanded to fill a 256 byte array.  This make two arrays that Wrzeszcz maintains, one for the key stream k[] and the other for the substition state s[].

The key generator formula is as follows:

k[c] = (k[c] + k[(c + 1) % 256] + j) % 256

j = (j + k[c] + c) % 256

swap(s[c], s[j])

output = s[j] ^ k[c]

The output is XOR'd with the input bytes to make the encrypted or decrypted stream.

Wrzeszcz can encrypt 1GB of data in 2.1 seconds on some hardware and faster.

