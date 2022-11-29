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
    return __compute_prob(_ins, _outs, bct, ir, switch_prob, cipher)


def create_bct(cipher):
    input_size = cipher.AX_BOX_INPUT_SIZE
    output_size = cipher.AX_BOX_OUTPUT_SIZE
    bct = [[0] * (2 ** output_size) for _ in range(2 ** input_size)]
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
    return bct


def __compute_prob(_ins: list, _outs: list, bct: list, ir: int, switch_prob: int, cipher):
    x_ind = cipher.FOUR_X_INDEXES
    y_ind = cipher.FOUR_Y_INDEXES
    if cipher.AX_BOX_INPUT_SIZE == 6:
        x_ind = cipher.SIX_X_INDEXES
        y_ind = cipher.SIX_Y_INDEXES

    # Small Register
    _in = 0 if ir is None else ir
    for x in x_ind:
        _in = (_in << 1) | _ins[SMALL_REGISTER_OFFSET + x]
    _out = 0
    if cipher.AX_BOX_OUTPUT_SIZE == 1:
        _out = _outs[BIG_REGISTER_OFFSET + 13] ^ _ins[SMALL_REGISTER_OFFSET + 7] ^ _ins[SMALL_REGISTER_OFFSET + 12]
    ax_res = bct[_in][_out]
    switch_prob *= ax_res / cipher.TOTAL_NUM

    # Big Register
    _in = 0
    for y in y_ind:
        _in = (_in << 1) | _ins[BIG_REGISTER_OFFSET + y]
    _out = 0
    if cipher.AX_BOX_OUTPUT_SIZE == 1:
        _out = _outs[SMALL_REGISTER_OFFSET + 0] ^ _ins[BIG_REGISTER_OFFSET + 18] ^ _ins[BIG_REGISTER_OFFSET + 7]
    ax_res = bct[_in][_out]
    switch_prob *= ax_res / cipher.TOTAL_NUM

    return switch_prob


def block_invalid_switches(beta, parameters, block_func, stp_file):
    input_bits = num_to_bits(int(beta, 16))
    cipher = parameters["cipher_obj"]
    ir = cipher.IR[parameters["em_ir"]]
    bct = parameters["bct"]
    x_ind = cipher.FOUR_X_INDEXES
    y_ind = cipher.FOUR_Y_INDEXES
    if cipher.AX_BOX_INPUT_SIZE == 6:
        x_ind = cipher.SIX_X_INDEXES
        y_ind = cipher.SIX_Y_INDEXES
    # small register
    __b_f(x_ind, input_bits, cipher, bct, block_func, stp_file, parameters, ir, SMALL_REGISTER_OFFSET)

    # big register
    __b_f(y_ind, input_bits, cipher, bct, block_func, stp_file, parameters, None, BIG_REGISTER_OFFSET)


def __b_f(indexes, input_bits, cipher, bct, block_func, stp_file, parameters, ir, offset):
    _in = ir if ir is not None else 0
    for x in indexes:
        _in = (_in << 1) | input_bits[offset + x]
    for _out in range(2 ** cipher.AX_BOX_OUTPUT_SIZE):
        # if prob is zero, block this trail.
        if bct[_in][_out] == 0:
            for x in indexes:
                a = "X0[{0}:{0}]".format(x)
                b = "{}".format(bin(input_bits[offset + x]))
                block_func(stp_file, a, b)
        # the initial trail, prob must be higher
        if ("X{}".format(parameters["lowertrail"]) not in parameters["boomerangVariables"] and
                parameters["bct"][_in][_out] != 2 ** cipher.AX_BOX_INPUT_SIZE):
            for x in indexes:
                a = "X0[{0}:{0}]".format(x)
                b = "{}".format(bin(input_bits[offset + x]))
                block_func(stp_file, a, b)
