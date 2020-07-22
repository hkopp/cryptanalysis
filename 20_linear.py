# Linear Cryptanalysis Toy Implementation

# Encryption is as follows: xor key0, then substitute, then xor key1
# So we have the simplest type of a sp-network (without the permutation)
# key sizes: key0=4bit, key1=4 bit, so key is 8 bit
# block length is 4 bit
# sbox width is 4 bit

#same cipher as in 01_differential.py

import random

s = [12, 2, 13, 14, 3, 10, 0, 9, 5, 8, 15, 11, 4, 7, 1, 6]  # chosen by fair dice roll

s_rev = [s.index(0),
            s.index(1),
            s.index(2),
            s.index(3),
            s.index(4),
            s.index(5),
            s.index(6),
            s.index(7),
            s.index(8),
            s.index(9),
            s.index(10),
            s.index(11),
            s.index(12),
            s.index(13),
            s.index(14),
            s.index(15)]

# fixed point of sbox[11]=11
# no idea if that is bad

def sbox(x):
    return s[x]

def sbox_rev(x):
    return s_rev[x]



def round_function(input, key):
    return sbox(key ^ input)


def encrypt(input, key0, key1):
    return round_function(input, key0) ^ key1


def number_of_nonzero_bits(num):
    return bin(num).count("1")


def get_linear_approximation_table():
    """The entry t_ij is the number of times the sum of the input mask of i is equal to the sum of the output mask of j.
    I.e., how often does this linear relationship hold?"""
    print("[*] Computing linear approximation table.")
    lin_approx_table = [[0 for x in range(16)] for y in range(16)]
    for in_mask in range(16):
        for out_mask in range(16):
            for input0 in range(16):
                masked_in = input0 & in_mask
                masked_out = sbox(input0) & out_mask
                if (number_of_nonzero_bits(masked_in) - number_of_nonzero_bits(masked_out)) % 2 == 0:
                    lin_approx_table[in_mask][out_mask] +=1
    return lin_approx_table


def matrix_pretty_print(matrix):
    # https://stackoverflow.com/questions/13214809/pretty-print-2d-python-list
    s = [[str(e) for e in row] for row in matrix]
    lens = [max(map(len, col)) for col in zip(*s)]
    fmt = '  '.join('{{:{}}}'.format(x) for x in lens)
    table = [fmt.format(*row) for row in s]
    print('\n'.join(table))



lin_approx_table = get_linear_approximation_table()
matrix_pretty_print(lin_approx_table)

#16  8   8   8   8   8   8   8   8   8   8   8   8   8   8   8 
#8   6   12  10  6   8   6   8   10  8   10  8   12  6   8   10
#8   10  8   10  8   10  4   6   10  4   6   8   6   8   6   8 
#8   8   8   8   6   2   6   10  8   8   8   8   6   10  6   10
#8   8   8   8   6   10  6   10  4   8   8   4   10  10  6   6 
#8   6   8   6   4   10  8   6   6   8   6   8   6   8   10  12
#8   10  12  6   10  8   10  8   10  8   6   4   8   10  8   10
#8   8   8   8   8   8   8   8   8   4   12  8   8   12  12  8 
#8   10  8   6   10  8   6   8   6   8   6   12  12  10  8   10
#8   8   8   12  8   8   8   12  8   8   4   8   8   8   12  8 
#8   8   4   8   10  6   6   6   8   8   8   4   10  6   10  10
#8   6   8   10  8   6   12  6   6   4   6   8   10  8   6   8 
#8   10  8   6   4   6   8   6   10  8   6   8   10  8   10  4 
#8   8   12  8   10  6   6   6   4   8   8   8   6   6   10  6 
#8   8   8   12  8   8   8   4   8   12  8   8   8   12  8   8 
#8   14  8   10  6   8   10  8   6   8   10  8   8   6   8   10


# We can see that an input mask of 2 corresponds to an output mask of 1 a total of 12 times.
# This means that the sign of input & 2 is "too often" equal to the sign of output & 1.
# Note that we could instead target low entries, where the linear relationship holds "too rarely".
# Constructing a distinguisher from this observation is easy.


# I will implement key_recovery maybe in the future
