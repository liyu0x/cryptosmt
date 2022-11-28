"""
Created on Nov 20, 2022

@author: li yu
"""

SMALL_REGISTER_OFFSET = 19
BIG_REGISTER_OFFSET = 0


def num_to_bits(num: int, length=32):
    binary = bin(num)[2:]
    res = [int(c) for c in binary]
    for z in range(len(res), length):
        res.insert(0, 0)
    return res


def check_bct(_in: int, _out: int, bct: list, ir_index: int, switch_prob: int, cipher):
    # (_in,_out) = L2(big) [0...19] |L1(small)[20...32]
    _ins = num_to_bits(_in)
    _outs = num_to_bits(_out)
    ir = cipher.IR[ir_index]
    if cipher.AX_BOX_INPUT_SIZE == 4:
        switch_prob = __4_bits_compute(_ins, _outs, bct, ir, switch_prob, cipher)
    else:
        switch_prob = __6_bits_compute(_ins, _outs, bct, ir, switch_prob, cipher)
    return switch_prob


def create_bct(cipher, bct):
    input_size = cipher.AX_BOX_INPUT_SIZE
    output_size = cipher.AX_BOX_OUTPUT_SIZE
    for delta_in in range(2 ** input_size):
        for delta_out in range(2 ** output_size):
            for x in range(2 ** input_size):
                x_delta_in = x ^ delta_in
                x_delta_out = x ^ delta_out
                x_delta_all = x ^ delta_in ^ delta_out
                if output_size == 1:
                    r_x = cipher.ax_box(x, input_size)
                    r_x_delta_in = cipher.ax_box(x_delta_in, input_size)
                    r_x_delta_out = cipher.ax_box(x_delta_out, input_size)
                    r_x_delta_all = cipher.ax_box(x_delta_all, input_size)
                else:
                    r_x = x | cipher.ax_box(x, input_size)
                    r_x_delta_in = x_delta_in | cipher.ax_box(x_delta_in, input_size)
                    r_x_delta_out = x_delta_out | cipher.ax_box(x_delta_out, input_size)
                    r_x_delta_all = x_delta_all | cipher.ax_box(x_delta_all, input_size)
                if r_x ^ r_x_delta_in ^ r_x_delta_out ^ r_x_delta_all == 0:
                    bct[delta_in][delta_out] += 1
    return


def __4_bits_compute(_ins: list, _outs: list, bct: list, ir: int, switch_prob: int, cipher):
    # small register, length: 13 (3&IR)^(5 & 8)^7 ^ 12
    _in = ir  # x0
    _in = (_in << 1) | _ins[SMALL_REGISTER_OFFSET + 3]  # x1
    _in = (_in << 1) | _ins[SMALL_REGISTER_OFFSET + 5]  # x2
    _in = (_in << 1) | _ins[SMALL_REGISTER_OFFSET + 8]  # x3
    _out = _outs[BIG_REGISTER_OFFSET + 13] ^ _ins[SMALL_REGISTER_OFFSET + 7] ^ _ins[SMALL_REGISTER_OFFSET + 12]
    ax_res = bct[_in][_out]
    if ax_res > 0:
        switch_prob *= ax_res / (cipher.AX_BOX_INPUT_SIZE * cipher.AX_BOX_OUTPUT_SIZE)

    # big register length: 19 (3&8)^(10&12)^18^7
    _in = _ins[3]
    _in = (_in << 1) | _ins[BIG_REGISTER_OFFSET + 8]
    _in = (_in << 1) | _ins[BIG_REGISTER_OFFSET + 10]
    _in = (_in << 1) | _ins[BIG_REGISTER_OFFSET + 12]

    _out = _outs[SMALL_REGISTER_OFFSET + 0] ^ _ins[BIG_REGISTER_OFFSET + 18] ^ _ins[BIG_REGISTER_OFFSET + 7]

    ax_res = bct[_in][_out]
    if ax_res > 0:
        switch_prob *= ax_res / (cipher.AX_BOX_INPUT_SIZE * cipher.AX_BOX_OUTPUT_SIZE)
    return switch_prob


def __6_bits_compute(_ins: list, _outs: list, bct: list, ir: int, switch_prob: int, cipher):
    # small register, length: 13 (3&IR)^(5 & 8)^7 ^ 12
    _in = ir  # x0
    _in = (_in << 1) | _ins[SMALL_REGISTER_OFFSET + 3]
    _in = (_in << 1) | _ins[SMALL_REGISTER_OFFSET + 5]
    _in = (_in << 1) | _ins[SMALL_REGISTER_OFFSET + 7]
    _in = (_in << 1) | _ins[SMALL_REGISTER_OFFSET + 8]
    _in = (_in << 1) | _ins[SMALL_REGISTER_OFFSET + 12]

    _out = _ins[SMALL_REGISTER_OFFSET + 3]
    _out = (_out << 1) | _ins[SMALL_REGISTER_OFFSET + 5]
    _out = (_out << 1) | _ins[SMALL_REGISTER_OFFSET + 7]
    _out = (_out << 1) | _ins[SMALL_REGISTER_OFFSET + 8]
    _out = (_out << 1) | _ins[SMALL_REGISTER_OFFSET + 12]
    _out = (_out << 1) | _outs[BIG_REGISTER_OFFSET + 13]
    ax_res = bct[_in][_out]
    if ax_res > 0:
        switch_prob *= ax_res / (cipher.AX_BOX_INPUT_SIZE * cipher.AX_BOX_OUTPUT_SIZE)

    # big register length: 19 (3&8)^(10&12)^18^7
    _in = _ins[3]
    _in = (_in << 1) | _ins[BIG_REGISTER_OFFSET + 7]
    _in = (_in << 1) | _ins[BIG_REGISTER_OFFSET + 8]
    _in = (_in << 1) | _ins[BIG_REGISTER_OFFSET + 10]
    _in = (_in << 1) | _ins[BIG_REGISTER_OFFSET + 12]
    _in = (_in << 1) | _ins[BIG_REGISTER_OFFSET + 18]

    _out = _ins[BIG_REGISTER_OFFSET + 7]
    _out = (_out << 1) | _ins[BIG_REGISTER_OFFSET + 8]
    _out = (_out << 1) | _ins[BIG_REGISTER_OFFSET + 10]
    _out = (_out << 1) | _ins[BIG_REGISTER_OFFSET + 12]
    _out = (_out << 1) | _ins[BIG_REGISTER_OFFSET + 18]
    _out = (_out << 1) | _outs[SMALL_REGISTER_OFFSET + 0]
    ax_res = bct[_in][_out]
    if ax_res > 0:
        switch_prob *= ax_res / (cipher.AX_BOX_INPUT_SIZE * cipher.AX_BOX_OUTPUT_SIZE)
    return switch_prob


def block_invalid_switches(parameters):
    return
