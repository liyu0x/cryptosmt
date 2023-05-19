def num_to_bits(num: int, length=32):
    bits = []
    for i in range(length):
        bits.append(num & 0b1)
        num >>= 1
    bits.reverse()
    return bits


def bits_to_num(bits: list):
    res = 0
    for i, b in enumerate(bits):
        res <<= 1
        res += b
    return res


def ax_box(x, bit_size):
    res = 0
    for i in range(bit_size - 1, 0, -2):
        x0 = x >> i & 0b1
        x1 = x >> (i - 1) & 0b1
        res ^= (x0 & x1)
    return res


def ax_box2(x):
    res = 0
    x0 = x >> 2 & 0b11
    x1 = x & 0b11
    res ^= (x0 & x1)
    return res


def ax_box_2_bits(x):
    x0 = x >> 1 & 0b1
    x1 = x & 0b1
    return x0 & x1
