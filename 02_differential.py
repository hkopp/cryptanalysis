# Differential Cryptanalysis Toy Implementation

# Two Round SPN
# block size 9 bit, sbox size = 3 bits, keylength=27 bits
# see 02_differential.jpg
# Note that the keys are called key0, key1, and key2, whereas in the jpg they are called k1, k2 and k3.

# xor k1
# sbox, sbox, sbox
# permutation: 0, 3, 6, 1, 4, 7, 2, 5, 8
# xor k2
# sbox, sbox, sbox
# xor k3

import random

s = [3, 6, 4, 5, 1, 7, 2, 0]  # chosen by fair dice roll
sbox_rev = [s.index(0),
            s.index(1),
            s.index(2),
            s.index(3),
            s.index(4),
            s.index(5),
            s.index(6),
            s.index(7)]

SBOX_RANGE=len(s) # not the bit length of the sbox, but its range of possible input values

def sbox(x):
    return s[x]

p = [0, 3, 6, 1, 4, 7, 2, 5, 8]

def pbox(x):
    y = 0
    for i in range(len(p)):
        if (x & (1 << i)) != 0:
            y = y ^ (1 << p[i])
    return y

# import math
# SBOX_BITSIZE = int(math.log2(len(sbox)))

def round_function(input, key):
    return pbox(sbox(key ^ input))


def encrypt(input, key0, key1):
    return sbox(round_function(input, key0) ^ key1) ^ key2


def get_difference_distribution_table():
    print("[*] Computing difference distribution table.")
    diff_dist_table = [[0 for x in range(SBOX_RANGE)] for y in range(SBOX_RANGE)]
    for in_diff in range(SBOX_RANGE):
        for input0 in range(SBOX_RANGE):
            input1 = input0 ^ in_diff
            out_diff = sbox(input0) ^ sbox(input1)
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

#8  0  0  0  0  0  0  0
#0  2  2  0  0  2  2  0
#0  0  0  4  0  0  0  4
#0  2  2  0  0  2  2  0
#0  2  2  0  0  2  2  0
#0  0  0  0  4  0  0  4
#0  2  2  0  0  2  2  0
#0  0  0  4  4  0  0  0


# TODO: The code for breaking the cipher is missing.
# We need to chain the differential characteristics in order to get a differential for the whole cipher.
