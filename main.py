from essentials import *


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
                  |    0x02   |  |         0x03        |  | 0x01 | | 0x01 |
        s[0][c] = x_2[s[0][c]] ^ x_2[s[1][c]] ^ s[1][c] ^ s[2][c] ^ s[3][c]'''

    for c in range(4):
        a = s[0][c]
        b = s[1][c]
        d = s[2][c]
        s[0][c] = x_2[s[0][c]] ^ x_2[s[1][c]] ^ s[1][c] ^ s[2][c] ^ s[3][c]
        s[1][c] = a ^ x_2[s[1][c]] ^ x_2[s[2][c]] ^ s[2][c] ^ s[3][c]
        s[2][c] = a ^ b ^ x_2[s[2][c]] ^ x_2[s[3][c]] ^ s[3][c]
        s[3][c] = x_2[a] ^ a ^ b ^ d ^ x_2[s[3][c]]


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
    s[1] = s[1][3:] + s[1][:3]
    s[2] = s[2][2:] + s[2][:2]
    s[3] = s[3][1:] + s[3][:1]


def invmix_column(s):
    ''' Multiplication with inverse polynomial a-1(x) = {0b}x3 + {0d}x2 + {09}x + {0e}
                 | since (0x0e = 0x02 ^ 0x04 ^ 0x08) & (0x0b = 0x02 ^ 0x08 ^ 0x01) & (0x0d = 0x04 ^ 0x08 ^ 0x01) & (0x09 = 0x08 ^ 0x01)|
                 |                          0x0e                           | |                    0x0b                       | |                      0x0d                          | |              0x09             |
                 |     0x02     | |      0x04     | |        0x08          | | 0x01  | |    0x02    | |          0x08        | | 0x01  | |      0x04       | |          0x08        | | 0x01  | |        0x08         |
        s[0][c] = x_2[s[0][c]] ^ x_2[x_2[s[0][c]]] ^ x_2[x_2[x_2[s[0][c]]]] ^ s[1][c] ^ x_2[s[1][c]] ^ x_2[x_2[x_2[s[1][c]]]] ^ s[2][c] ^ x_2[x_2[s[2][c]]] ^ x_2[x_2[x_2[s[2][c]]]] ^ s[3][c] ^ x_2[x_2[x_2[s[3][c]]]] '''
    for c in range(4):
        a = s[0][c]
        b = s[1][c]
        d = s[2][c]
        s[0][c] = x_2[s[0][c]] ^ x_2[x_2[s[0][c]]] ^ x_2[x_2[x_2[s[0][c]]]] ^ \
                  s[1][c] ^ x_2[s[1][c]] ^ x_2[x_2[x_2[s[1][c]]]] ^ \
                  s[2][c] ^ x_2[x_2[s[2][c]]] ^ x_2[x_2[x_2[s[2][c]]]] ^ \
                  s[3][c] ^ x_2[x_2[x_2[s[3][c]]]]

        s[1][c] = a ^ x_2[x_2[x_2[a]]] ^ \
                  x_2[s[1][c]] ^ x_2[x_2[s[1][c]]] ^ x_2[x_2[x_2[s[1][c]]]] ^ \
                  s[2][c] ^ x_2[s[2][c]] ^ x_2[x_2[x_2[s[2][c]]]] ^ \
                  s[3][c] ^ x_2[x_2[s[3][c]]] ^ x_2[x_2[x_2[s[3][c]]]]

        s[2][c] = a ^ x_2[x_2[a]] ^ x_2[x_2[x_2[a]]] ^ \
                  b ^ x_2[x_2[x_2[b]]] ^ \
                  x_2[s[2][c]] ^ x_2[x_2[s[2][c]]] ^ x_2[x_2[x_2[s[2][c]]]] ^ \
                  s[3][c] ^ x_2[s[3][c]] ^ x_2[x_2[x_2[s[3][c]]]]

        s[3][c] = a ^ x_2[a] ^ x_2[x_2[x_2[a]]] ^ \
                  b ^ x_2[x_2[b]] ^ x_2[x_2[x_2[b]]] ^ \
                  d ^ x_2[x_2[x_2[d]]] ^ \
                  x_2[s[3][c]] ^ x_2[x_2[s[3][c]]] ^ x_2[x_2[x_2[s[3][c]]]]


def key_expansion(key):
    temp1 = [int(key[2*i:2*i + 2], 16) for i in range(len(key)//2)]
    temp = [temp1[4*i: 4*i + 4] for i in range(len(temp1)//4)]

    # For 128 bit key
    if len(temp1) == 16:
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

    # For 192 bit key
    elif len(temp1) == 24:
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

    # For 256 bit key
    elif len(temp1) == 32:
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
    key_grid = []
    for i in range(len(temp)//4):
        a = temp[4*i:4*i+4]
        h = [[a[j][i] for j in range(len(a))] for i in range(len(a[0]))]
        key_grid.append(h)
    return key_grid


def debug(m, s):
    S = [[s[j][i]for j in range(4)] for i in range(4)]
    b = []
    for i in S:
        for j in i:
            b.append(f"{j:0>2x}")
    c = ''.join(i for i in b)
    print(m + ' \t' + c)


def encrypt(m, key):
    key_grid = key_expansion(key)
    temp = [int(m[2*i:2*i + 2], 16) for i in range(len(m)//2)]
    # Declaring state matrix
    s = [[temp[i * 4 + j] for i in range(4)] for j in range(4)]
    debug('round[ 0].input', s)
    debug('round[ 0].k_sch', key_grid[0])
    # adding first round key
    add_roundkey(s, key_grid[0])
    # rounds for different key sizes
    if len(key)//2 == 16:
        for round in range(9):
            debug('round[ {}].start'.format(round+1), s)
            sub_bytes(s)
            debug('round[ {}].s_box'.format(round+1), s)
            mix_row(s)
            debug('round[ {}].s_row'.format(round+1), s)
            mix_column(s)
            debug('round[ {}].m_col'.format(round+1), s)
            debug('round[ {}].k_sch'.format(round+1), key_grid[round+1])
            add_roundkey(s, key_grid[round+1])
        last_round = 10
    elif len(key)//2 == 24:
        for round in range(11):
            debug('round[ {}].start'.format(round+1), s)
            sub_bytes(s)
            debug('round[ {}].s_box'.format(round+1), s)
            mix_row(s)
            debug('round[ {}].s_row'.format(round+1), s)
            mix_column(s)
            debug('round[ {}].m_col'.format(round+1), s)
            debug('round[ {}].k_sch'.format(round+1), key_grid[round+1])
            add_roundkey(s, key_grid[round+1])
        last_round = 12
    elif len(key)//2 == 32:
        for round in range(13):
            debug('round[ {}].start'.format(round+1), s)
            sub_bytes(s)
            debug('round[ {}].s_box'.format(round+1), s)
            mix_row(s)
            debug('round[ {}].s_row'.format(round+1), s)
            mix_column(s)
            debug('round[ {}].m_col'.format(round+1), s)
            debug('round[ {}].k_sch'.format(round+1), key_grid[round+1])
            add_roundkey(s, key_grid[round+1])
        last_round = 14
    # last round with no mix column
    debug('round[{}].start'.format(last_round), s)
    sub_bytes(s)
    debug('round[{}].s_box'.format(last_round), s)
    mix_row(s)
    debug('round[{}].s_row'.format(last_round), s)
    debug('round[{}].k_sch'.format(last_round), key_grid[-1])
    add_roundkey(s, key_grid[-1])
    debug('round[{}].output'.format(last_round), s)


def decrypt(c, key):
    key_grid = key_expansion(key)
    temp = [int(c[2*i:2*i +2], 16) for i in range(len(c)//2)]
    chunks = [temp[16 * i:16 * i + 16] for i in range(len(c) // 32)]
    for chunk in chunks:
        # Declaring state matrix
        s = [[chunk[i * 4 + j] for i in range(4)] for j in range(4)]
        debug('round[ 0].input', s)
        debug('round[ 0].ik_sch', key_grid[-1])
        # first round with no mix column
        add_roundkey(s, key_grid[-1])
        # rounds for different key sizes
        if len(key)//2 == 16:
            for round in range(9):
                debug('round[ {}].istart'.format(round+1), s)
                invmix_row(s)
                debug('round[ {}].is_row'.format(round+1), s)
                invsub_bytes(s)
                debug('round[ {}].is_box'.format(round + 1), s)
                debug('round[ {}].ik_sch'.format(round + 1), key_grid[-2-round])
                add_roundkey(s, key_grid[-2-round])
                debug('round[ {}].ik_add'.format(round + 1), s)
                invmix_column(s)
            last_round = 10
        elif len(key)//2 == 24:
            for round in range(11):
                debug('round[ {}].istart'.format(round+1), s)
                invmix_row(s)
                debug('round[ {}].is_row'.format(round+1), s)
                invsub_bytes(s)
                debug('round[ {}].is_box'.format(round + 1), s)
                debug('round[ {}].ik_sch'.format(round + 1), key_grid[-2-round])
                add_roundkey(s, key_grid[-2-round])
                debug('round[ {}].ik_add'.format(round + 1), s)
                invmix_column(s)
            last_round = 12
        elif len(key)//2 == 32:
            for round in range(13):
                debug('round[ {}].istart'.format(round+1), s)
                invmix_row(s)
                debug('round[ {}].is_row'.format(round+1), s)
                invsub_bytes(s)
                debug('round[ {}].is_box'.format(round + 1), s)
                debug('round[ {}].ik_sch'.format(round + 1), key_grid[-2-round])
                add_roundkey(s, key_grid[-2-round])
                debug('round[ {}].ik_add'.format(round + 1), s)
                invmix_column(s)
            last_round = 14
        # adding round key in the last round
        debug('round[{}].istart'.format(last_round), s)
        invmix_row(s)
        debug('round[{}].is_row'.format(last_round), s)
        invsub_bytes(s)
        debug('round[{}].is_box'.format(last_round), s)
        debug('round[{}].ik_sch'.format(last_round), key_grid[0])
        add_roundkey(s, key_grid[0])
        debug('round[{}].ioutput'.format(last_round), s)


if __name__ == '__main__':
    message = '00112233445566778899aabbccddeeff'
    key = '000102030405060708090a0b0c0d0e0f1011121314151617'
    # encrypt(message, key)
    cipher = 'dda97ca4864cdfe06eaf70a0ec0d7191'
    decrypt(cipher, key)
