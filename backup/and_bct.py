import numpy


def general_and_operation(x: int, involve_bits_length: int):
    bit_extraction = 0
    for _ in range(involve_bits_length + 1):
        bit_extraction <<= 1
        bit_extraction |= 0b1
    a0 = x & bit_extraction
    a1 = x >> involve_bits_length & bit_extraction

    # temp
    # a0 = x & 0x11
    # a1 = x >> 2 & 0x11
    return a0 & a1


def general_and_xor_connection(x: int, involve_bits_length: int):
    involve_bits_length = int(involve_bits_length / 2)
    r1 = general_and_operation(x, involve_bits_length)
    r2 = general_and_operation(x >> (2 * involve_bits_length), involve_bits_length)
    return r1 ^ r2


def create_and_bct(non_linear, involve_bits_length: int):
    """
    use specified non-part function to create AND-BCT
    :param non_linear: non-liner function
    :param involve_bits_length: length of a number involving AND-operation
    :return: AND-BCT
    """
    table_size = 2 ** (involve_bits_length * 2)
    and_bct = numpy.zeros((table_size, table_size), dtype=int)
    for delta_in in range(table_size):
        for nabla_out in range(table_size):
            for x1 in range(table_size):
                x2 = x1 ^ delta_in
                x3 = x1 ^ nabla_out
                x4 = x1 ^ delta_in ^ nabla_out
                y1 = non_linear(x1, involve_bits_length)
                y2 = non_linear(x2, involve_bits_length)
                y3 = non_linear(x3, involve_bits_length)
                y4 = non_linear(x4, involve_bits_length)
                if y1 ^ y2 ^ y3 ^ y4 == 0:
                    and_bct[delta_in][nabla_out] += 1
    return and_bct


#_1 = create_and_bct(general_and_operation, 1)
_2 = create_and_bct(general_and_xor_connection, 2)
