# CipherTool

A Tool for breaking Caesar and Vigenere ciphers for english plaintext. It also supports encryption and decryption operations with given keys.


## Usage

```
➜  CipherTool git:(master) ✗ python3 CipherTool.py -h
usage: CipherTool.py [-h] -t {vigenere,caesar} (-c CIPHERTEXT | -p PLAINTEXT) [-k KEY]

Decryption and Encryption Tool for common ciphers like caesar and vigenere. If a key is not given, hueristics are used to find the english plaintext

optional arguments:
  -h, --help            show this help message and exit
  -t {vigenere,caesar}, --cipher-type {vigenere,caesar}
                        Type of cipher to use for encryption or decryption.
  -c CIPHERTEXT, --ciphertext CIPHERTEXT
                        Cipher text to decrpy
  -p PLAINTEXT, --plaintext PLAINTEXT
                        Plain text to encrypt
  -k KEY, --key KEY     Key for either decryption or encryption
```

## Algortithm for breaking vigenere cipher


The algorithm is taken from here:    \
http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher-part-2/

The idea is to assign a score to the decrypted text which indicates the closeness to english sentences. Using the score, we can steer our search for the key
in the right direction. We first brute force the key length. For each key length we guess the key letter by letter.

### English score of text

For calculating the score, we already have the frequency of common quadrams and trigrams in english language. Based on the frequency, we give a score to each
n-gram as: `log10(frequency of n-gram / sum of all frequencies)`. Also for n-grams not present, we take the frequency as 0.01 to avoid invalid log.
We then find all the n-grams in the given text, and add their scores.

Suppose we have the text "HELLO WORLD" and we want to find its score i.e. how close it is to english language.
The 4-grams in this text are: `["HELL", "ELLO", "WORL", "ORLD"]`. We add the score of all these n-grams already computed to get the score of "HELLO WORLD".

### Finding key

We brute force over the length of the key from 3 to 10. Now, for each key length:    \
We built the key incrementally i.e. to find the $i^{th}$ character of the key, each alphabet is tried and appended to the best key found so far.
The score of the key found so far is the english score of the plaintext after decryption from that key. NOTE: the score is calculated only for those parts of
plaintext that were decoded from the key found so far. So, if the key length is 8, and we have found 5 characters (rest are 'a' that act as padding),
then the score will be calculated only using the plaintext decrypted by first 5 characters of the key

The complexity of searching through keys becomes $O(26*N)$ instead of $O(26^N)$, where $N$ is key length
