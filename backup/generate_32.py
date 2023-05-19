import and_bct
import random
import util

TEST_ROUND = 4

L1_INDEXES_ORI = [[5, 8], [4, 7], [3, 6], [2, 5]]
L1_INDEXES_ORI = [[e + 19 for e in n] for n in L1_INDEXES_ORI]
L1_INDEXES_ORI_OUT = [[e + TEST_ROUND for e in n] for n in L1_INDEXES_ORI]

L2_INDEXES_ORI = [[3, 8, 10, 12], [2, 7, 9, 11], [1, 6, 8, 10], [0, 5, 7, 9]]
L2_INDEXES_ORI_OUT = [[e + TEST_ROUND for e in n] for n in L2_INDEXES_ORI]

L1_RIGHT = [12 - i for i in range(TEST_ROUND)]
L2_RIGHT = [18 - i for i in range(TEST_ROUND)]


def bct_tool(bct):
    # List the probabilities of 1 and 0 for BCT
    size = len(bct[0])
    p_0 = {}
    p_1 = {}
    for i in range(size):
        for j in range(size):
            if bct[i][j] == size:
                if i not in p_1:
                    p_1[i] = [j]
                else:
                    p_1[i].append(j)
            else:
                if i not in p_0:
                    p_0[i] = [j]
                else:
                    p_0[i].append(j)
    return p_0, p_1


def check_diff_2(bct, ori, ori_out, _in_bits, _out_bits):
    for i in range(len(ori)):
        in_diff_indies = ori[i]
        out_diff_indies = ori_out[i]
        _input = _in_bits[in_diff_indies[1]] << 1 | _in_bits[in_diff_indies[0]]
        _output = _out_bits[out_diff_indies[1]] << 1 | _out_bits[out_diff_indies[0]]
        if bct[_input][_output] == 0:
            return False
    return True


def check_diff_4(bct, ori, ori_out, _in_bits, _out_bits):
    for i in range(len(ori)):
        in_diff_indies = ori[i]
        out_diff_indies = ori_out[i]
        _input = _in_bits[in_diff_indies[3]] << 3 | _in_bits[in_diff_indies[2]] << 2 | _in_bits[
            in_diff_indies[1]] << 1 | _in_bits[in_diff_indies[0]]
        _output = _out_bits[out_diff_indies[3]] << 3 | _out_bits[out_diff_indies[2]] << 2 | _out_bits[
            out_diff_indies[1]] << 1 | _out_bits[out_diff_indies[0]]
        if bct[_input][_output] == 0:
            return False
    return True


def generate_and_bct_cvc_conditions(in_diff, out_diff, number):
    l1_bct = and_bct.create_and_bct(and_bct.general_and_operation, 1)
    l2_bct = and_bct.create_and_bct(and_bct.general_and_xor_connection, 2)

    counter = 0

    results = {}

    while counter < number:
        n_in_diff = in_diff if in_diff is not None else random.randint(0, 2 ** 32)
        n_out_diff = out_diff if out_diff is not None else random.randint(0, 2 ** 32)
        n_in_diff_bits = util.num_to_bits(n_in_diff)
        n_out_diff_bits = util.num_to_bits(n_out_diff)
        n_in_diff_bits.reverse()
        n_out_diff_bits.reverse()
        if not check_diff_2(l1_bct, L1_INDEXES_ORI, L1_INDEXES_ORI_OUT, n_in_diff_bits, n_out_diff_bits):
            continue
        if not check_diff_4(l2_bct, L2_INDEXES_ORI, L2_INDEXES_ORI_OUT, n_in_diff_bits, n_out_diff_bits):
            continue
        if n_in_diff not in results:
            results[n_in_diff] = []
        results[n_in_diff].append(n_out_diff)
        counter += 1

    return results


def temp_run():
    results = generate_and_bct_cvc_conditions(0x00C01080, None, 100)
    for result in results:
        for r in results[result]:
            print("IN_DIFF:{0}, OUT_DIFF:{1}".format(hex(result), hex(r)))


