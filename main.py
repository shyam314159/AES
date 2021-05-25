from essentials import *


# Multiply with 0x02 in GF(256)
def xtime(a): return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def sub_bytes(s):
    # Substitution round
    for i in range(4):
        for j in range(4):
            s[i][j] = Sbox[s[i][j]]


def mix_row(s):
    s[1] = s[1][1:] + s[1][:1]
    s[2] = s[2][2:] + s[2][:2]
    s[3] = s[3][3:] + s[3][:3]


def mix_column(s):
    ''' Multiplication with a(x) = {03}x3 + {01}x2 + {01}x + {02}
        | since 0x03 = 0x01 ^ 0x02 |
                  |    0x02     |  |           0x03        |  | 0x01 | | 0x01 |
        s[0][c] = xtime(s[0][c]) ^ xtime(s[1][c]) ^ s[1][c] ^ s[2][c] ^ s[3][c]'''

    for c in range(4):
        s[0][c] = xtime(s[0][c]) ^ xtime(s[1][c]) ^ s[1][c] ^ s[2][c] ^ s[3][c]
        s[1][c] = s[0][c] ^ xtime(s[1][c]) ^ xtime(s[2][c]) ^ s[2][c] ^ s[3][c]
        s[2][c] = s[0][c] ^ s[1][c] ^ xtime(s[2][c]) ^ xtime(s[3][c]) ^ s[3][c]
        s[3][c] = xtime(s[0][c]) ^ s[0][c] ^ s[1][c] ^ s[2][c] ^ xtime(s[3][c])


def add_roundkey(s, round_key):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= round_key[i][j]


def invsub_bytes(s):
    # Inverse substitution round
    for i in range(4):
        for j in range(4):
            s[i][j] = InvSbox[s[i][j]]


def invmix_row(s):
    s[1] = s[1][:1] + s[1][1:]
    s[2] = s[2][:2] + s[2][2:]
    s[3] = s[3][:3] + s[3][3:]


def invmix_column(s):
    ''' Multiplication with inverse polynomial a-1(x) = {0b}x3 + {0d}x2 + {09}x + {0e}
                 | since (0x0e = 0x02 ^ 0x04 ^ 0x08) & (0x0b = 0x02 ^ 0x08 ^ 0x01) & (0x0d = 0x04 ^ 0x08 ^ 0x01) & (0x09 = 0x08 ^ 0x01)|
                 |                               0x0e                                  | |                        0x0b                           | |                          0x0d                                | |                 0x09                |
                 |     0x02     | |       0x04          | |           0x08             | | 0x01  | |     0x02     | |             0x08           | | 0x01  | |        0x04         | |             0x08           | | 0x01  | |           0x08            |
        s[0][c] = xtime(s[0][c]) ^ xtime(xtime(s[0][c])) ^ xtime(xtime(xtime(s[0][c]))) ^ s[1][c] ^ xtime(s[1][c]) ^ xtime(xtime(xtime(s[1][c]))) ^ s[2][c] ^ xtime(xtime(s[2][c])) ^ xtime(xtime(xtime(s[2][c]))) ^ s[3][c] ^ xtime(xtime(xtime(s[3][c])))'''
    for c in range(4):
        s[0][c] = xtime(s[0][c]) ^ xtime(xtime(s[0][c])) ^ xtime(xtime(xtime(s[0][c]))) ^ \
                  s[1][c] ^ xtime(s[1][c]) ^ xtime(xtime(xtime(s[1][c]))) ^\
                  s[2][c] ^ xtime(xtime(s[2][c])) ^ xtime(xtime(xtime(s[2][c]))) ^ \
                  s[3][c] ^ xtime(xtime(xtime(s[3][c])))

        s[1][c] = s[0][c] ^ xtime(xtime(xtime(s[0][c]))) ^ \
                  xtime(s[1][c]) ^ xtime(xtime(s[1][c])) ^ xtime(xtime(xtime(s[1][c]))) ^ \
                  s[2][c] ^ xtime(s[2][c]) ^ xtime(xtime(xtime(s[2][c]))) ^ \
                  s[3][c] ^ xtime(xtime(s[3][c])) ^ xtime(xtime(xtime(s[3][c])))

        s[2][c] = s[0][c] ^ xtime(xtime(s[0][c])) ^ xtime(xtime(xtime(s[0][c]))) ^ \
                  s[1][c] ^ xtime(xtime(xtime(s[1][c]))) ^ \
                  xtime(s[2][c]) ^ xtime(xtime(s[2][c])) ^ xtime(xtime(xtime(s[2][c]))) ^ \
                  s[3][c] ^ xtime(s[3][c]) ^ xtime(xtime(xtime(s[3][c])))

        s[3][c] = s[0][c] ^ xtime(s[0][c]) ^ xtime(xtime(xtime(s[0][c]))) ^ \
                  s[1][c] ^ xtime(xtime(s[1][c])) ^ xtime(xtime(xtime(s[1][c]))) ^ \
                  s[2][c] ^ xtime(xtime(xtime(s[2][c]))) ^ \
                  xtime(s[3][c]) ^ xtime(xtime(s[3][c])) ^ xtime(xtime(xtime(s[3][c])))


def key_expansion(key):
    temp = [ord(i) for i in key]
    # Making a grid
    temp = [temp[4 * i:4 * i + 4] for i in range(int(len(temp) / 4))]

    # For 128 bit key
    if len(key) == 16:
        for i in range(10):
            # Taking last 4 for key expansion and further process
            w = temp[-1]
            # Rotate
            w = w[1:] + w[:1]
            # Substitution
            for b in range(len(w)):
                w[b] = Sbox[w[b]]
            # Xor with rcon
            w[0] ^= Rcon[i]
            for c in range(4):
                # Taking last 4th list to xor and generate new values of key grid
                e = temp[-4]
                # Xoring
                xor = [e[wo] ^ w[wo] for wo in range(4)]
                # Appending the new list to key grid
                temp.append(xor)
                # Changing w value to last list
                w = temp[-1]
        return temp

    # For 192 bit key
    elif len(key) == 24:
        for i in range(8):
            # Taking last 4 for key expansion and further process
            w = temp[-1]
            # Rotate
            w = w[1:] + w[:1]
            # Substitution
            for b in range(len(w)):
                w[b] = Sbox[w[b]]
            # Xor with rcon
            w[0] ^= Rcon[i]
            for c in range(6):
                # Taking last 6th list to xor and generate new values of key grid
                e = temp[-6]
                # Xoring
                xor = [e[wo] ^ w[wo] for wo in range(4)]
                # Appending the new list to key grid
                temp.append(xor)
                # Changing w value to last list
                w = temp[-1]
                # Breaks if length of key grid = 52
                if len(temp) == 52:
                    break
        return temp

    # For 256 bit key
    elif len(key) == 32:
        for i in range(7):
            # Taking last 4 for key expansion and further process
            w = temp[-1]
            # Rotate
            w = w[1:] + w[:1]
            # Substitution
            for b in range(len(w)):
                w[b] = Sbox[w[b]]
            # Xor with rcon
            w[0] ^= Rcon[i]
            for c in range(8):
                # Taking last 8th list to xor and generate new values of key grid
                e = temp[-8]
                # Substitution for 4th round
                if c == 4:
                    w = [Sbox[w1] for w1 in w]
                # Xoring
                xor = [e[wo] ^ w[wo] for wo in range(4)]
                # Appending the new list to key grid
                temp.append(xor)
                # Changing w value to last list
                w = temp[-1]
                # Breaks if length of key grid = 60
                if len(temp) == 60:
                    break
        return temp


def encrypt(m, key):
    key_grid = key_expansion(key)
    # For padding
    pad = 'abcdefghijklmn'
    if len(m) % 16:
        m += '{' + pad[:15 - len(m) % 16]
    # Breaking into list of list of 16 bytes
    chunks = [m[16 * i:16 * i + 16] for i in range(len(m) // 16)]
    cipher = ''
    for chunk in chunks:
        # Declaring state matrix
        s = [[ord(chunk[i + j * 4]) for i in range(4)] for j in range(4)]
        # adding first round key
        s = [[s[j][i] ^ key_grid[j][i] for i in range(4)] for j in range(4)]
        # rounds for different key sizes
        if len(key) == 16:
            for round in range(9):
                sub_bytes(s)
                mix_row(s)
                mix_column(s)
                add_roundkey(s, key_grid[4 * round + 4:4 * round + 8])
        elif len(key) == 24:
            for round in range(11):
                sub_bytes(s)
                mix_row(s)
                mix_column(s)
                add_roundkey(s, key_grid[4 * round + 4:4 * round + 8])
        elif len(key) == 32:
            for round in range(13):
                sub_bytes(s)
                mix_row(s)
                mix_column(s)
                add_roundkey(s, key_grid[4 * round + 4:4 * round + 8])
        # last round with no mix column
        sub_bytes(s)
        mix_row(s)
        add_roundkey(s, key_grid[-4:])
        # making it a string
        for i in range(4):
            for j in range(4):
                cipher += chr(s[i][j])
    return cipher


def decrypt(c, key):
    key_grid = key_expansion(key)
    chunks = [c[16 * i:16 * i + 16] for i in range(len(c) // 16)]
    message = ''
    for chunk in chunks:
        # Declaring state matrix
        s = [[ord(chunk[i + j * 4]) for i in range(4)] for j in range(4)]

        # first round with no mix column
        add_roundkey(s, key_grid[-4:])
        invmix_row(s)
        invsub_bytes(s)
        # rounds for different key sizes
        if len(key) == 16:
            for round in range(9, 0, -1):
                add_roundkey(s, key_grid[4 * round + 4:4 * round + 8])
                invmix_column(s)
                invmix_row(s)
                invsub_bytes(s)
        elif len(key) == 24:
            for round in range(11, 0, -1):
                add_roundkey(s, key_grid[4 * round + 4:4 * round + 8])
                invmix_column(s)
                invmix_row(s)
                invsub_bytes(s)
        elif len(key) == 32:
            for round in range(12, -1, -1):
                add_roundkey(s, key_grid[4 * round + 4:4 * round + 8])
                invmix_column(s)
                invmix_row(s)
                invsub_bytes(s)
        # adding round key in the last round
        s = [[s[j][i] ^ key_grid[j][i] for i in range(4)] for j in range(4)]
        # making it a string
        for i in range(4):
            for j in range(4):
                message += chr(s[i][j])
    return message


if __name__ == '__main__':
    message = '1234567890123456'
    key = 'abcdefghijklmnop'
    a = encrypt(message, key)
    print(decrypt(a, key))
