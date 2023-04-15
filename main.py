# RSA Decryption Algorithm
# Alexander Allis - Assignment 5
import math


# 1. Factor N into two prime numbers, p and q. Use brute force.
# Fermat's Factorization Method
# Source: https://medium.com/nerd-for-tech/heres-how-quadratic-sieve-factorization-works-1c878bc94f81

def factor_number(n):
    x = math.sqrt(n)
    if x % 1 != 0:
        x = x // 1
        x = x + 1
    while x < N:
        if math.sqrt(math.pow(x, 2) - N) % 1 == 0:
            ySquared = math.pow(x, 2) - N
            y = math.sqrt(ySquared)
            a = x + y
            b = x - y
            return a, b
        x = x + 1


# 2. Determine φ(N)

def phi_n(p, q):
    return (p - 1) * (q - 1)


# 3. Compute the decryption exponent, 'a,' as the inverse of b modulo φ(N), from Cryptography Theory and Practice, 4ed
# Returns the inverse of b modulo "modulus"
def compute_inverse(modulus, num):
    a_0 = modulus
    b_0 = num
    t_0 = 0
    t = 1
    q = math.floor(a_0 / b_0)
    r = a_0 - (q * b_0)
    while r > 0:
        temp = (t_0 - (q * t)) % modulus
        t_0 = t
        t = temp
        a_0 = b_0
        b_0 = r
        q = math.floor(a_0 / b_0)
        r = a_0 - (q * b_0)
    if b_0 != 1:
        return -1
    return t


# 3. Returns x^c modulo n, from Cryptography Theory and Practice, 4ed
def square_and_multiply(x, c, n):
    binary_exponent = []
    while c > 0:
        binary_exponent.append(c % 2)
        c = c // 2
    binary_exponent.reverse()

    z = 1
    for i in range(len(binary_exponent)):
        z = (z * z) % n
        if binary_exponent[i] == 1:
            z = (z * x) % n
    return z


def encrypt(decrypted_integer, exponent, modulus):
    pt = decrypted_integer.copy()
    # Encrypt to Check
    for i in range(len(pt)):
        pt[i] = square_and_multiply(pt[i], exponent, modulus)
    return pt


# 4. Decrypt the ciphertext, obtaining the plaintext in the form of a sequence of elements in Zn.
def decrypt(ciphertext, exponent, modulus):
    ct = ciphertext.copy()
    for i in range(len(ct)):
        ct[i] = square_and_multiply(ct[i], exponent, modulus)

    return ct


def decode(decryption_integers):
    letters_by_index = []
    for number in decryption_integers:
        plaintext1 = number % 26
        number = number - plaintext1

        plaintext2_ = number % math.pow(26, 2)
        plaintext2 = plaintext2_ // math.pow(26, 1)
        number = number - plaintext2_

        plaintext3_ = number % math.pow(26, 3)
        plaintext3 = plaintext3_ // math.pow(26, 2)
        number = number - plaintext3_

        plaintext4_ = number % math.pow(26, 4)
        plaintext4 = plaintext4_ // math.pow(26, 3)
        number = number - plaintext4_

        plaintext5_ = number % math.pow(26, 5)
        plaintext5 = plaintext5_ // math.pow(26, 4)
        number = number - plaintext5_

        plaintext6_ = number // math.pow(26, 6)
        plaintext6 = number // math.pow(26, 5)
        number = number - plaintext6_

        letters_by_index.append(plaintext6)
        letters_by_index.append(plaintext5)
        letters_by_index.append(plaintext4)
        letters_by_index.append(plaintext3)
        letters_by_index.append(plaintext2)
        letters_by_index.append(plaintext1)

    return letters_by_index


def index_to_character(i):
    return chr(int(i) + 65)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    # encryption = [encrypt_message()]

    N = 2177994659
    b = 65537

    f = open('rsa-cipher', "r")
    cipherTextInt = []
    for line in f:
        cipherTextInt.append(line.strip('\n'))
    cipherTextInt = list(map(int, line.split()))

    i, j = factor_number(N)
    phi_N = phi_n(i, j)
    a = int(compute_inverse(phi_N, b))
    # if a * b % phi_N == 1:
    #     print("true")
    decryption = decrypt(cipherTextInt, a, N)
    recomputed_ciphertext = encrypt(decryption, b, N)
    # if recomputed_ciphertext[0] == cipherTextInt[0]:
    #     print("Finally")
    plaintext = decode(decryption)

    # print result
    for i in plaintext:
        print(index_to_character(i), end='')
