"""
Created on Nov 20, 2022

@author: li yu
"""


def num_to_bits(num: int, length=32):
    bits = []
    for i in range(length):
        bits.append(num & 0x1)
        num >>= 1
    return bits


def check_bct(_in: int, _out: int, bct: list, switch_prob: int, cipher):
    # (_in,_out) = L2(big) [0...19] |L1(small)[20...32]
    _ins = num_to_bits(_in)
    _outs = num_to_bits(_out)
    return __compute_prob(_ins, _outs, bct, switch_prob, cipher)


def create_bct(cipher):
    bct_size = cipher.BCT_INPUT_SIZE
    bct = [[0] * (2 ** bct_size) for _ in range(2 ** bct_size)]
    for delta_in in range(2 ** bct_size):
        for delta_out in range(2 ** bct_size):
            for x in range(2 ** bct_size):
                x_delta_in = x ^ delta_in
                x_delta_out = x ^ delta_out
                x_delta_in_out = x ^ delta_in ^ delta_out
                r_x = cipher.ax_box(x)
                r_x_delta_in = cipher.ax_box(x_delta_in)
                r_x_delta_out = cipher.ax_box(x_delta_out)
                r_x_delta_int_out = cipher.ax_box(x_delta_in_out)
                if r_x ^ r_x_delta_in ^ r_x_delta_out ^ r_x_delta_int_out == 0:
                    bct[delta_in][delta_out] += 1
    return bct


def __compute_prob(_ins: list, _outs: list, bct: list, switch_prob: int, cipher):
    # Small Register
    _in = 0
    for x in cipher.SMALL_REG_INPUT_INDEXES:
        _in = (_in << 1) | _ins[x]
    _out = 0
    for x in [i + 1 for i in cipher.SMALL_REG_INPUT_INDEXES]:
        _out = (_out << 1) | _ins[x]
    ax_res = bct[_in][_out]
    switch_prob *= ax_res / (2 ** cipher.BCT_INPUT_SIZE)

    # Big Register
    _in = 0
    for y in cipher.BIG_REG_INPUT_INDEXES:
        _in = (_in << 1) | _ins[y]
    _out = 0
    for y in [i + 1 for i in cipher.BIG_REG_INPUT_INDEXES]:
        _out = (_out << 1) | _ins[y]
    ax_res = bct[_in][_out]
    switch_prob *= ax_res / (2 ** cipher.BCT_INPUT_SIZE)

    return switch_prob


def block_invalid_switches(beta, parameters, block_func, stp_file):
    input_bits = num_to_bits(int(beta, 16))
    cipher = parameters["cipher_obj"]
    bct = parameters["bct"]
    # small register
    __b_f(cipher.SMALL_REG_INPUT_INDEXES, input_bits, cipher, bct, block_func, stp_file, parameters)

    # big register
    __b_f(cipher.BIG_REG_INPUT_INDEXES, input_bits, cipher, bct, block_func, stp_file, parameters)


def __b_f(indexes, input_bits, cipher, bct, block_func, stp_file, parameters):
    _in = 0
    # for x in indexes:
    #     _in = (_in << 1) | input_bits[x]
    # for _out in range(2 ** len(indexes)):
    #     # if prob is zero, block this trail.
    #     if bct[_in][_out] == 0:
    #         for x in indexes:
    #             a = "X0[{0}:{0}]".format(x)
    #             b = "{}".format(bin(input_bits[x]))
    #             block_func(stp_file, a, b)
    #     # the initial trail, prob must be higher
    #     if ("X{}".format(parameters["lowertrail"]) not in parameters["boomerangVariables"] and
    #             parameters["bct"][_in][_out] != 2 ** cipher.BCT_INPUT_SIZE):
    #         for x in indexes:
    #             a = "X0[{0}:{0}]".format(x)
    #             b = "{}".format(bin(input_bits[x]))
    #             block_func(stp_file, a, b)
