import argparse
from queue import PriorityQueue
from itertools import permutations
from math import log10, floor
from tabulate import tabulate

# Algorithm for breaking Vigenere cipher is inspired from here:
# http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher-part-2/


class EnglishFitness():

    def __init__(self, file):
        self.file = file
        self.weight = {}
        self.total_weight = 0
        with open(self.file) as f:
            for line in f.readlines():
                ngram, value = line.split()
                self.weight[ngram] = int(value)
                self.weight[ngram.lower()] = int(value)
                self.total_weight += int(value)
        self.n = len(ngram)
        for ngram in self.weight:
            self.weight[ngram] = log10(
                floor(self.weight[ngram]) / self.total_weight)
        self.nearly_zero_weight = log10(0.01 / self.total_weight)

    def find_score(self, text):
        score = 0
        for i in range(len(text) - self.n + 1):
            ngram = text[i:i + self.n]
            if ngram in self.weight:
                score += self.weight[ngram]
            else:
                score += self.nearly_zero_weight
        return score

    def normalise_from_score(self, results):
        n = len(results)
        for i in range(n):
            # Percentage score of i^th element
            # (original score is in log scale):
            #      10^{si} / (10^{s1} + ... + 10^{sn})
            #   =  1 / (10^{(s1 - si)} + ... + 10^{(sn - si)})
            denominator = 0
            for j in range(n):
                exp = results[j]["score"] - results[i]["score"]
                if exp > 300:
                    denominator = 10**400
                    break
                denominator += pow(10, exp)
            results[i]["probability"] = round(1 / denominator, 4)
        results.sort(key=lambda x: x["probability"], reverse=True)
        return results


class Caesar():

    def get_key(self, key):
        try:
            return int(key)
        except Exception:
            print("[!] Caesar key should be integer")
            exit(0)

    def get_base_char(self, c):
        if c.islower():
            return 'a'
        return 'A'

    def get_result(self, value, probability, key):
        return {"value": value, "probability": probability, "key": key}

    def encrypt(self, plaintext, key):
        ciphertext = ''
        key = self.get_key(key)
        for c in plaintext:
            # Change only if 'A-Z' or 'a-z'
            if ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z')):
                base_char = self.get_base_char(c)
                base_val = ord(c) - ord(base_char)
                ciphertext += chr(ord(base_char) + (base_val + key) % 26)
            else:
                ciphertext += c
        return ciphertext

    def decrypt_with_key(self, ciphertext, key=None):
        key = self.get_key(key)
        result = self.get_result(self.encrypt(ciphertext, -key), 100, key)
        return [result]

    def decrypt_without_key(self, ciphertext):
        results = []
        quadram_fitness = EnglishFitness('english_quadgrams.txt')
        for key in range(1, 27):
            result = self.decrypt_with_key(ciphertext, key)[0]
            score = quadram_fitness.find_score(result["value"])
            result["key"] = key
            result["score"] = score
            results.append(result)
        quadram_fitness.normalise_from_score(results)
        return results[:5]

    def decrypt(self, ciphertext, key=None):
        if key is not None:
            return self.decrypt_with_key(ciphertext, key)
        return self.decrypt_without_key(ciphertext)


class Vigenere():

    def __init__(self):
        self.trigram_fitness = EnglishFitness('english_trigrams.txt')
        self.quadram_fitness = EnglishFitness('english_quadgrams.txt')

    def get_base_char(self, c):
        if c.islower():
            return 'a'
        return 'A'

    def encrypt(self, plaintext, key):
        ciphertext = ''
        caesar = Caesar()
        for i in range(len(plaintext)):
            p = plaintext[i]
            k = key[i % len(key)]
            base_char = self.get_base_char(k)
            c = caesar.encrypt(p, ord(k) - ord(base_char))
            ciphertext += c
        return ciphertext

    def decrypt_with_key(self, ciphertext, key):
        caesar = Caesar()
        plaintext = ''
        j = 0
        for i in range(len(ciphertext)):
            c = ciphertext[i]
            if ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z')):
                k = key[j]
                base_char = self.get_base_char(k)
                p = caesar.decrypt(c, ord(k) - ord(base_char))
                plaintext += p[0]["value"]
                j = (j + 1) % len(key)
            else:
                plaintext += c
        return [{"value": plaintext, "probability": 1, "key": key}]

    def insert_in_queue(self, q, value):
        if q.empty():
            q.put(value)
            return
        if q.full():
            curr_lowest = q.get()
            if curr_lowest[0] > value[0]:
                q.put(curr_lowest)
            else:
                q.put(value)
        else:
            q.put(value)

    def try_key_len(self, ciphertext, key_len):
        q = PriorityQueue(maxsize=100)
        for perm in permutations("abcdefghijklmnopqrstuvwxyz", 3):
            short_key = "".join(perm)
            complete_key = short_key + "a" * (key_len - len(short_key))
            plaintext = self.decrypt_with_key(ciphertext,
                                              complete_key)[0]["value"]
            score = 0
            for i in range(0, len(plaintext), key_len):
                score += self.trigram_fitness.find_score(plaintext[i:i + 3])
            self.insert_in_queue(q, (score, short_key))
        for rem_key in range(key_len - 3):
            curr_results = q.queue.copy()
            new_q = PriorityQueue(maxsize=50)
            for result in curr_results:
                for new_char in "abcdefghijklmnopqrstuvwxyz":
                    short_new_key = result[1] + new_char
                    complete_new_key = short_new_key + "a" * (
                        key_len - len(short_new_key))
                    plaintext = self.decrypt_with_key(
                        ciphertext, complete_new_key)[0]["value"]
                    score = 0
                    for i in range(0, len(plaintext), key_len):
                        score += self.quadram_fitness.find_score(
                            plaintext[i:i + len(short_new_key)])
                    self.insert_in_queue(new_q, (score, short_new_key))
            q = new_q
        return q

    def decrypt_without_key(self, ciphertext):
        ciphertext = ciphertext.lower()
        results_per_key = []
        for key_len in range(3, 11):
            print("[*] Trying key size: {}".format(key_len))
            q = self.try_key_len(ciphertext, key_len)
            val = None
            while not q.empty():
                val = q.get()
            key = val[1]
            plaintext = self.decrypt_with_key(ciphertext, key)[0]["value"]
            score = self.quadram_fitness.find_score(plaintext)
            results_per_key.append((score, key))
        final_results = []
        for result in results_per_key:
            key = result[1]
            plaintext = self.decrypt_with_key(ciphertext, key)[0]["value"]
            final_results.append({
                "value": plaintext,
                "score": result[0],
                "key": key
            })
        self.quadram_fitness.normalise_from_score(final_results)
        return final_results[:5]

    def decrypt(self, ciphertext, key=None):
        if key is not None:
            return self.decrypt_with_key(ciphertext, key)
        return self.decrypt_without_key(ciphertext)


class CipherTool:

    def __init__(self, type):
        self.type = type
        self.cipher = None
        if type == "vigenere":
            self.cipher = Vigenere()
        elif type == "caesar":
            self.cipher = Caesar()

    def decrypt(self, ciphertext, key=None):
        return self.cipher.decrypt(ciphertext, key)

    def encrypt(self, plaintext, key):
        return self.cipher.encrypt(plaintext, key)


def handle_args(args):
    type = args.cipher_type
    ciphertool = CipherTool(type)

    plaintext = args.plaintext
    ciphertext = args.ciphertext
    key = args.key
    # Encode plaintext
    if plaintext is not None:
        if key is None:
            print("[!] Provide a key for encryption")
            return
        ciphertext = ciphertool.encrypt(plaintext, key)
        print("[*] Encoded plain text:")
        print(ciphertext)
    # Decode ciphertext
    else:
        results = ciphertool.decrypt(ciphertext, key)
        print("[*] Possible Decoded cipher texts:")
        table = []
        for result in results:
            percentage = round(result["probability"] * 100)
            table.append([result["key"], result["value"], percentage])
        headers = ["Key", "Plaintext", "Percentage Confidence"]
        print(tabulate(table, headers=headers, tablefmt="github"))


def main():
    parser = argparse.ArgumentParser(
        description='''Decryption and Encryption Tool for common ciphers
        like caesar and vigenere. If a key is not given, hueristics are used
        to find the english plaintext''')
    parser.add_argument("-t",
                        "--cipher-type",
                        choices=["vigenere", "caesar"],
                        help='''
                        Type of cipher to use for encryption or decryption.
                        ''',
                        required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--ciphertext", help='''Cipher text to decrpy''')
    group.add_argument("-p", "--plaintext", help='''Plain text to encrypt''')
    parser.add_argument("-k",
                        "--key",
                        help='''Key for either decryption or encryption''')
    args = parser.parse_args()
    handle_args(args)


if __name__ == "__main__":
    main()
