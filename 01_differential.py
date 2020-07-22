# Differential Cryptanalysis Toy Implementation

# Encryption is as follows: xor key0, then substitute, then xor key1
# So we have the simplest type of a sp-network (without the permutation)
# key sizes: key0=4bit, key1=4 bit, so key is 8 bit
# block length is 4 bit
# sbox width is 4 bit

import random

sbox = [12, 2, 13, 14, 3, 10, 0, 9, 5, 8, 15, 11, 4, 7, 1, 6]  # chosen by fair dice roll
sbox_rev = [sbox.index(0),
            sbox.index(1),
            sbox.index(2),
            sbox.index(3),
            sbox.index(4),
            sbox.index(5),
            sbox.index(6),
            sbox.index(7),
            sbox.index(8),
            sbox.index(9),
            sbox.index(10),
            sbox.index(11),
            sbox.index(12),
            sbox.index(13),
            sbox.index(14),
            sbox.index(15)]

# fixed point of sbox[11]=11
# no idea if that is bad


def round_function(input, key):
    return sbox[key ^ input]


def encrypt(input, key0, key1):
    return round_function(input, key0) ^ key1


def get_difference_distribution_table():
    print("[*] Computing difference distribution table.")
    diff_dist_table = [[0 for x in range(16)] for y in range(16)]
    for in_diff in range(16):
        for input0 in range(16):
            input1 = input0 ^ in_diff
            out_diff = sbox[input0] ^ sbox[input1]
            diff_dist_table[in_diff][out_diff] = diff_dist_table[in_diff][out_diff] + 1
    return diff_dist_table


def matrix_pretty_print(matrix):
    # https://stackoverflow.com/questions/13214809/pretty-print-2d-python-list
    s = [[str(e) for e in row] for row in matrix]
    lens = [max(map(len, col)) for col in zip(*s)]
    fmt = '  '.join('{{:{}}}'.format(x) for x in lens)
    table = [fmt.format(*row) for row in s]
    print('\n'.join(table))


diff_dist_table = get_difference_distribution_table()
matrix_pretty_print(diff_dist_table)

# 16  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
# 0   0  0  4  2  0  0  2  0  4  0  0  0  2  2  0
# 0   4  0  6  0  2  0  0  0  0  2  0  2  0  0  0
# 0   0  4  0  0  0  2  2  0  0  4  0  0  0  2  2
# 0   2  0  0  0  0  0  2  2  0  0  0  0  4  2  4
# 0   2  2  0  2  0  2  0  0  2  2  0  2  0  2  0
# 0   0  0  0  4  0  0  0  0  0  0  4  4  0  4  0
# 0   0  2  2  0  2  0  2  2  2  0  0  0  2  0  2
# 0   2  2  0  0  2  0  2  0  2  2  0  0  2  0  2
# 0   2  0  0  4  0  4  2  2  0  0  0  0  0  2  0
# 0   0  2  2  2  0  2  0  2  2  0  0  2  0  2  0
# 0   0  0  0  0  4  0  4  0  0  0  4  0  4  0  0
# 0   0  4  0  0  2  2  0  4  0  0  0  2  0  0  2
# 0   0  0  0  0  0  4  0  0  0  0  8  0  0  0  4
# 0   4  0  0  2  2  0  0  0  4  0  0  2  2  0  0
# 0   0  0  2  0  2  0  0  4  0  6  0  2  0  0  0

# We see that an input difference of 13 leads to an output difference of 11
# with probability 1/2 (8/16)
# So we already built a distinguisher for the cipher.
print("[*] Choosing differential characteristic 13 -> 11")
# How? Well, we query a chosen-plaintext oracle with two plaintexts with difference 13.
# If the output difference is 11, then we probably deal with the cipher, instead of a
# random oracle.

# Next, we want to recover the key.
# Note that the key length is 8 bits, thus brute-forcing naively needs 2^8 steps.
# However, we brute-force only the first half of the key and compute the remaining half using
# basic algebra. Key guesses can then be validated using some known plaintext-ciphertext pair.
# Consequently, brute forcing needs 2^4=16 steps.

# Now, we use differential cryptanalysis and need less then 16 steps.
# As differential cryptanalysis is a chosen-plaintext attack, we can access an encryption oracle.

# Now, let us compute all possible intermediate values for which the differential characteristic 13 -> 11 holds.
# This can be done in a pre-processing phase.
# Note that there are 8 intermediate values, as that is the probability of the differential characteristic.
# Thus, we have many intermediate values, but it is easy to find a plaintext-ciphertext pair for which the characteristic holds.
# On the other hand, if the probability of the differential is low, then there are only few possible intermediate values, but
# it is hard to find a plaintext-ciphertext pair for which the differential characteristic holds.


def gen_possible_intermediate_values(input_diff, output_diff):
    good_pairs = []
    for input0 in range(16):
        input1 = input0 ^ input_diff
        if sbox[input0] ^ sbox[input1] == output_diff:
            good_pairs.append([input0, input1])
    return good_pairs


intermediate_values = gen_possible_intermediate_values(13, 11)
print("[*] Possible intermediate values: " + str(intermediate_values))


def gen_plain_cipher_pairs(input_diff, num):
    # Generate num plaintext, ciphertext pairs with fixed input difference.
    # Remember, this is a chosen plaintext attack
    # random key which we want to recover
    key = (random.randint(0, 15), random.randint(0, 15))
    print("[*] Real key: %s %s" % (key[0], key[1]))
    pairs = []
    for input0 in random.sample(range(16), num):
        input1 = input0 ^ input_diff
        output0 = encrypt(input0, key[0], key[1])
        output1 = encrypt(input1, key[0], key[1])
        pairs.append(((input0, input1), (output0, output1)))
    return pairs


plain_cipher_pairs = gen_plain_cipher_pairs(13, 3)
# We are using three pairs. This should be enough, but of course more is better.

# Next, we want to only take a look at the good plaintext-ciphertext pairs.
# These are those pairs, where the differential characteristic holds.


def find_good_pair(plain_cipher_pairs, output_diff):
    print("[*] Searching for good pairs.")
    for ((input0, input1), (output0, output1)) in plain_cipher_pairs:
        if output0 ^ output1 == output_diff:
            return ((input0, input1), (output0, output1))
    raise Exception("No good pair found.")

# If we have num plaintext-ciphertext pairs with the input difference 13,
# then approximately num/2 of these are good pairs, i.e., they have the output difference 11.


((good_p0, good_p1), (good_c0, good_c1)) = find_good_pair(plain_cipher_pairs, 11)

print("[*] Found a good pair: " + str(((good_p0, good_p1), (good_c0, good_c1))))

# For such a good pair, we know the 8 possible intermediate values before and after the sbox.
# Each of these intermediate values gives us a guess for the key.

# If we have guessed a key, we can validate it using the other (even bad) plaintext-ciphertext pair
# or some other known plaintext-ciphertext pair.


def validate_key(guessed_k0, guessed_k1):
    """Checks a key against known plaintext-ciphertext pair and returns True if the key is correct."""
    for ((input0, input1), (output0, output1)) in plain_cipher_pairs:
        if encrypt(input0, guessed_k0, guessed_k1) != output0:
            return False
        if encrypt(input1, guessed_k0, guessed_k1) != output1:
            return False
    return True


# All that is left is compute the possible keys, given the possible intermediate values before the sbox and check the keys.
# Note that we are still bruteforcing, but we are only bruteforcing 8 values, instead of 16.
def recover_key():
    print("[*] Brute-Forcing remaining key space")
    for (p0, p1) in intermediate_values:
        guessed_k0 = p0 ^ good_p0
        guessed_k1 = sbox[p0] ^ good_c0
        if validate_key(guessed_k0, guessed_k1):
            print("Recovered key --> %s %s" % (guessed_k0, guessed_k1))
        else:
            print("                  %s %s" % (guessed_k0, guessed_k1))


recover_key()
