#sha256.py
from itertools import product
from string import hexdigits


#helper functions as specified in the specification (FIPS 180-4)
def ch(x: int, y: int, z: int) -> int:
    '''The input x chooses whether to take the input from y or z'''
    return (x & y) ^ (~x & z)


def maj(x: int, y: int, z: int) -> int:
    '''Majority of the 3 inputs bits for x y and z at this index is returned'''
    return (x & y) ^ (x & z) ^ (y & z)


def rotr(num: int, shift: int, size: int = 32) -> int:
    '''Rotate an integer right'''
    return (num >> shift) | (num << size - shift)


def sigma0(num: int) -> int:
    '''As defined in the specification (FIPS 180-4)'''
    return (rotr(num, 2) ^ rotr(num, 13) ^ rotr(num, 22))


def sigma1(num: int) -> int:
    '''As defined in the specification (FIPS 180-4)'''
    return (rotr(num, 6) ^ rotr(num, 11) ^ rotr(num, 25))


def gamma0(num: int) -> int:
    '''As defined in the specification (FIPS 180-4)'''
    return (rotr(num, 7) ^ rotr(num, 18) ^ (num >> 3))


def gamma1(num: int) -> int:
    '''As defined in the specification (FIPS 180-4)'''
    return (rotr(num, 17) ^ rotr(num, 19) ^ (num >> 10))


#initialize array of round constants to the first 32 bits of the
#fractional parts of the cube roots of the first 64 primes
k = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
     0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
     0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
     0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
     0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
     0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

#ascii printable characters
apc = (' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-',
       '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';',
       '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
       'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
       'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e',
       'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
       't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~')


#main function to generate SHA-256 hash
def sha256_hash(message) -> str:
    '''Return a SHA-256 hash string from the message passed. The input message must be a 
    string, bytes or a bytearray object'''

    if (type(message) == bytearray):
        #input is of the correct type
        pass
    elif (type(message) == bytes):
        #make message mutable
        message = bytearray(message)
    elif (type(message) == str):
        #convert given input message string into bytearray
        message = bytearray(message, 'utf-8')
    else:
        return "Incorrect input type!"

    #pre-processing (padding)
    length = len(message) * 8  #number of bytes in message
    message.append(0x80)
    while (len(message) * 8 + 64) % 512 != 0:
        message.append(0x00)

    message += length.to_bytes(8, 'big')  # pad to 8 bytes (64 bits)

    # parsing
    blocks = []  # contains 512-bit chunks of message
    #Process the message in successive 512-bit chunks
    for i in range(0, len(message), 64):
        blocks.append(message[i:i + 64])

    #initialize hash value with the first 32 bits of the fractional parts of
    #the square roots of the first 8 primes
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h5 = 0x9b05688c
    h4 = 0x510e527f
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # SHA-256 Hash Computation
    for message_block in blocks:
        # prepare message schedule
        message_schedule = []
        for t in range(0, 64):
            if t <= 15:
                # adds the t'th 32 bit word of the block,
                # starting from leftmost word
                # 4 bytes at a time
                message_schedule.append(bytes(message_block[t * 4:(t * 4) +
                                                            4]))
            else:
                term1 = gamma1(int.from_bytes(message_schedule[t - 2], 'big'))
                term2 = int.from_bytes(message_schedule[t - 7], 'big')
                term3 = gamma0(int.from_bytes(message_schedule[t - 15], 'big'))
                term4 = int.from_bytes(message_schedule[t - 16], 'big')

                # append a 4-byte byte object
                schedule = ((term1 + term2 + term3 + term4) % 2**32).to_bytes(
                    4, 'big')
                message_schedule.append(schedule)

        assert len(message_schedule) == 64

        # initialize working variables to current hash values
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        #compression function main loop
        for t in range(64):
            t1 = ((h + sigma1(e) + ch(e, f, g) + k[t] +
                   int.from_bytes(message_schedule[t], 'big')) % 2**32)

            t2 = (sigma0(a) + maj(a, b, c)) % 2**32

            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2**32

        #add the compressed chunk to the current hash value
        h0 = (h0 + a) % 2**32
        h1 = (h1 + b) % 2**32
        h2 = (h2 + c) % 2**32
        h3 = (h3 + d) % 2**32
        h4 = (h4 + e) % 2**32
        h5 = (h5 + f) % 2**32
        h6 = (h6 + g) % 2**32
        h7 = (h7 + h) % 2**32

    #produce the final hash value (big-endian):
    digest = bytearray()
    for h in [h0, h1, h2, h3, h4, h5, h6, h7]:
        digest += h.to_bytes(4, 'big')
    return digest.hex()


def sha256_find(digest: str) -> str:
    '''Try finding the original message with the given digest by brute-forcing. The given input must be a valid SHA-256 digest, 
    which is a hexadecimal string object of length 64'''

    #verify length of given digest and check if it is hexadecimal
    if (len(digest) != 64 or not set(digest).issubset(hexdigits)):
        return 'Invalid SHA-256 hash'

    i = 1
    while 1:
        cp = list(
            product(apc, repeat=i)
        )  #all possible combination of input strings using ascii printable characters
        for j in range(95**i):
            string = ''.join(cp[j])
            if (sha256_hash(string) == digest):
                return string
        i += 1
    return "Not found!"
