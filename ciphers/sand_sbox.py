from ciphers.cipher import AbstractCipher
from parser import stpcommands
import util
import itertools


class Sand(AbstractCipher):
    name = 'sand'

    alpha = 0

    beta = 1

    def __init__(self):
        self.PERM = None
        self.G0_BOX = [0, 1, 2, 0xb, 4, 5, 6, 0xf, 8, 9, 0xa, 3, 0xd, 0xc, 7, 0xe]
        self.G1_BOX = [0, 1, 2, 3, 4, 7, 6, 5, 8, 9, 0xe, 0xd, 0xc, 0xf, 0xa, 0xb]

    def createSTP(self, filename, parameters):
        word_size = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]
        switch_start_round = parameters["switchStartRound"]
        switch_rounds = parameters["switchRounds"]

        e0_start_search_num = 0
        e0_end_search_num = rounds if switch_start_round == -1 else switch_start_round
        em_start_search_num = rounds if switch_start_round == -1 else switch_start_round
        em_end_search_num = (
            rounds if switch_start_round == -1 else em_start_search_num + switch_rounds
        )
        e1_start_search_num = (
            rounds if switch_start_round == -1 else switch_start_round + switch_rounds
        )
        e1_end_search_num = rounds

        block_size = word_size // 2

        if word_size == 32:
            self.PERM = [7, 4, 1, 6, 3, 0, 5, 2]
        elif word_size == 64:
            self.PERM = [14, 15, 8, 9, 2, 3, 12, 13, 6, 7, 0, 1, 10, 11, 4, 5]

        with open(filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Sand{} w={} Rounds={}\n\n\n".format(word_size, weight,
                                                                                   rounds))
            stp_file.write(header)
            command = ""
            variables = initial_file(rounds, block_size, weight, stp_file)

            # loading init diff
            # self.pre_round(stp_file, xl[0], xr[0], xl[1], xr[1], block_size)

            for i in range(e0_start_search_num, e0_end_search_num):
                self.setup_round(stp_file, variables["in_left"][i], variables["in_right"][i],
                                 variables["in_left"][i + 1], variables["in_right"][i + 1],
                                 variables["g0_rot"][i], variables["g0_box_out"][i],
                                 variables["g1_rot"][i], variables["g1_box_out"][i],
                                 variables["g01_xor_out"][i], variables["perm_out"][i], variables["w"][i], word_size)
            # BCT
            # for i in range(em_start_search_num, em_end_search_num):
            #     self.bct_operator(stp_file, xl[i], yr[i + 1], g0_rot[i]
            #                       , g0_xor_out[i], g1_rot[i],
            #                       g1_xor_out[i], g12_xor_out[i], perm_out[i],
            #                       w[i], and_out[i], and_f[i], block_size)

            # for i in range(e1_start_search_num, e1_end_search_num):
            #     self.setup_round(stp_file, yl[i], yr[i], yl[i + 1], yr[i + 1], g0_rot[i]
            #                      , g0_xor_out[i], g1_rot[i],
            #                      g1_xor_out[i], g12_xor_out[i], perm_out[i],
            #                      w[i], and_out[i], and_f[i], block_size)

            command += self.pre_handle(parameters)
            stp_file.write(command)
            # stpcommands.assertNonZero(stp_file, [variables["in_left"][0], variables["in_right"][0]], block_size)
            if switch_rounds > 0:
                stpcommands.assertNonZero(stp_file, [variables["in_left"][rounds], variables["in_right"][rounds]],
                                          block_size)

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)
            stpcommands.setupQuery(stp_file)

    def pre_round(self, stp_file, in_left, in_right, out_left, out_right, block_size):
        re_sharp = util.sand_t(block_size)
        command = ""
        for i in range(block_size):
            command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]);\n".format(out_left, i, in_left, re_sharp[i])
            command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]);\n".format(out_right, i, in_right, re_sharp[i])
        stp_file.write(command)

    def bct_operator(self, stp_file, xl, yr, g0_rot
                     , g0_xor_out, g1_rot,
                     g1_xor_out, g12_xor_out, perm_out,
                     w, and_out, and_f, block_size):

        nibble = block_size // 4
        x0_index = util.sand_rot_nibble(block_size, self.alpha)
        command = ""
        # in G0   x{3} AND x{2}
        x0_3 = x0_index[3]
        x0_2 = x0_index[2]

        for i in range(nibble):
            command += "ASSERT({0}[{2}:{2}]&{1}[{3}:{3}]={1}[{2}:{2}]&{0}[{3}:{3}]);\n".format(
                xl, yr, x0_3[i], x0_2[i]
            )

        #  (x{3} AND x{2} XOR x{0}) AND x{1}
        x0_0 = x0_index[0]
        x0_1 = x0_index[1]

        for i in range(nibble):
            command += ("ASSERT(BVXOR({0}[{2}:{2}]&{0}[{3}:{3}], {0}[{4}:{4}])&{1}[{5}:{5}]="
                        "BVXOR({1}[{2}:{2}]&{1}[{3}:{3}], {1}[{4}:{4}])&{0}[{5}:{5}]);\n").format(
                xl, yr, x0_3[i], x0_2[i], x0_0[i], x0_1[i],

            )

        # in G1   x{1} AND x{3}
        x1_index = util.sand_rot_nibble(block_size, self.beta)
        x1_3 = x1_index[3]
        x1_1 = x1_index[1]

        for i in range(nibble):
            command += "ASSERT({0}[{2}:{2}]&{1}[{3}:{3}]={1}[{2}:{2}]&{0}[{3}:{3}]);\n".format(
                xl, yr, x1_3[i], x1_1[i])

        x1_2 = x1_index[2]
        x1_0 = x1_index[0]

        #  (x{3} AND x{1} XOR x{2}) AND x{0}
        for i in range(nibble):
            command += ("ASSERT(BVXOR({0}[{2}:{2}]&{0}[{3}:{3}], {0}[{4}:{4}])&{1}[{5}:{5}]="
                        "BVXOR({1}[{2}:{2}]&{1}[{3}:{3}], {1}[{4}:{4}])&{0}[{5}:{5}]);\n").format(
                xl, yr, x1_3[i], x1_1[i], x1_2[i], x1_0[i]

            )

        stp_file.write(command)

    def setup_round(self, stp_file, in_left, in_right, out_left, out_right, g0_rot, g0_box_out, g1_rot,
                    g1_box_out, g01_xor_out, perm_out, w, block_size, switch=False):

        command = "ASSERT({} = {});\n".format(out_right, in_left)

        group_size = 8

        g0_box_trails = get_valid_from_s_box(self.G0_BOX)
        g1_box_trails = get_valid_from_s_box(self.G1_BOX)

        # G_0
        g0_rot_index = util.sand_rot(block_size, self.alpha)

        if self.alpha != 0:
            for i in range(block_size):
                command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]);\n".format(g0_rot, i, in_left, g0_rot_index[i])
        else:
            command += "ASSERT({0}={1});\n".format(g0_rot, in_left)

        for i in range(group_size):
            # consist of 8 s_box

            indexes = [i, group_size + i, 2 * group_size + i, 3 * group_size + i]
            # command += add4bitSbox(g0_box_trails, g0_rot, g0_box_out, w, indexes)

        # G_1
        g1_rot_index = util.sand_rot(block_size, self.beta)

        if self.beta != 0:
            for i in range(block_size):
                command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]);\n".format(g1_rot, i, in_left, g1_rot_index[i])
        else:
            command += "ASSERT({0}={1});\n".format(g1_rot, in_left)

        # G_1
        for i in range(group_size):
            indexes = [i, group_size + i, 2 * group_size + i, 3 * group_size + i]
            # command += add4bitSbox(g1_box_trails, g1_rot, g1_box_out, w, indexes)

        # G1 xor G2
        command += "ASSERT({0} = BVXOR({1},{2}));\n".format(g01_xor_out, g0_box_out, g1_box_out)

        # P_out
        if block_size == 32:
            for i in range(block_size // 8):
                for j, k in enumerate([7, 4, 1, 6, 3, 0, 5, 2]):
                    command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(perm_out, i * 8 + k,
                                                                               g01_xor_out, i * 8 + j)

        command += ("ASSERT({0} = BVXOR({1},{2}));\n".format(out_left, in_right, perm_out))

        stp_file.write(command)

    def get_cluster_params(self, parameters, prob, total_prob):
        pass

    def create_cluster_parameters(self, new_parameters, characteristic):
        r = new_parameters['rounds']
        # Cluster Search
        trails_data = characteristic.getData()
        new_parameters["blockedCharacteristics"].clear()
        new_parameters["fixedVariables"].clear()

        input_diff_l = trails_data[0][0]
        input_diff_r = trails_data[0][1]

        # output diff
        output_diff_l = trails_data[r][2]
        output_diff_r = trails_data[r][3]

        new_parameters["fixedVariables"]["XL0"] = input_diff_l
        new_parameters["fixedVariables"]["XR0"] = input_diff_r

        new_parameters["fixedVariables"]["YL{}".format(r)] = output_diff_l
        new_parameters["fixedVariables"]["YR{}".format(r)] = output_diff_r

    def get_diff_hex(self, parameters, characteristics):
        switch_start_round = parameters['switchStartRound']
        switch_rounds = parameters['switchRounds']
        r = parameters['rounds']
        trails_data = characteristics.getData()
        # input diff
        input_diff_l = trails_data[0][0]
        input_diff_r = trails_data[0][1]
        input_diff = input_diff_l + input_diff_r.replace("0x", "")

        # output diff
        output_diff_l = trails_data[r][2]
        output_diff_r = trails_data[r][3]
        output_diff = output_diff_l + output_diff_r.replace("0x", "")

        # switch diff
        switch_input_diff_l = trails_data[switch_start_round][0]
        switch_input_diff_r = trails_data[switch_start_round][1]
        switch_output_diff_l = trails_data[switch_start_round + switch_rounds][2]
        switch_output_diff_r = trails_data[switch_start_round + switch_rounds][3]
        switch_input = switch_input_diff_l + switch_input_diff_r.replace("0x", "")
        switch_output = switch_output_diff_l + switch_output_diff_r.replace("0x", "")

        return input_diff, switch_input, switch_output, output_diff

    def pre_handle(self, param):
        if 'countered_trails' not in param:
            return ""
        characters = param["countered_trails"]
        word_size = param['wordsize']
        command = ""
        if len(characters) > 0:
            r = param['rounds']
            command = "ASSERT(NOT("
            for characteristic in characters:
                trails_data = characteristic.getData()
                # input diff
                input_diff_l = trails_data[0][0]
                input_diff_r = trails_data[0][1]

                # output diff
                output_diff_l = trails_data[r][2]
                output_diff_r = trails_data[r][3]

                str1 = "(BVXOR(XL0,{0})|BVXOR(XR0, {1}) | BVXOR(XL{2}, {3}) | BVXOR(XR{2}, {4}))".format(
                    input_diff_l,
                    input_diff_r,
                    r,
                    output_diff_l,
                    output_diff_r)
                command += str1
                command += "&"
            command = command[:-1]
            command += "=0x{}));\n".format('0' * (8))
        return command

    def getFormatString(self):
        return ['XL', 'XR', 'YL', 'YR', 'AROT', 'AXOROUT', 'BROT', 'BXOROUT', 'ABXOROUT', 'POUT', 'ANDF', 'w']


def initial_file(rounds, block_size, weight, stp_file):
    xl = ["XL{}".format(i) for i in range(rounds + 1)]
    xr = ["XR{}".format(i) for i in range(rounds + 1)]
    yl = ["YL{}".format(i) for i in range(rounds + 1)]
    yr = ["YR{}".format(i) for i in range(rounds + 1)]
    g0_rot = ["AROT{}".format(i) for i in range(rounds)]
    g0_box_out = ["ABOXOUT{}".format(i) for i in range(rounds)]
    g1_rot = ["BROT{}".format(i) for i in range(rounds)]
    g1_box_out = ["BBOXOUT{}".format(i) for i in range(rounds)]
    g01_xor_out = ["ABXOROUT{}".format(i) for i in range(rounds)]
    perm_out = ["POUT{}".format(i) for i in range(rounds)]
    w = ["w{}".format(i) for i in range(rounds)]

    stpcommands.setupVariables(stp_file, xl, block_size)
    stpcommands.setupVariables(stp_file, xr, block_size)
    stpcommands.setupVariables(stp_file, yl, block_size)
    stpcommands.setupVariables(stp_file, yr, block_size)
    stpcommands.setupVariables(stp_file, g0_rot, block_size)
    stpcommands.setupVariables(stp_file, g0_box_out, block_size)
    stpcommands.setupVariables(stp_file, g1_rot, block_size)
    stpcommands.setupVariables(stp_file, g1_box_out, block_size)
    stpcommands.setupVariables(stp_file, g01_xor_out, block_size)
    stpcommands.setupVariables(stp_file, perm_out, block_size)
    stpcommands.setupVariables(stp_file, w, block_size)
    stpcommands.setupWeightComputation(stp_file, weight, w, block_size)
    return {"in_left": xl, "in_right": xr, "out_left": yl, "out_right": yr, "g0_rot": g0_rot, "g0_box_out": g0_box_out,
            "g1_rot": g1_rot, "g1_box_out": g1_box_out, "perm_out": perm_out, "w": w, "g01_xor_out": g01_xor_out}


def get_valid_from_s_box(s_box):
    assert (len(s_box) == 16)

    ddt = [[0] * 16 for _ in range(16)]

    for x in range(16):
        for y in range(16):
            ddt[x ^ y][s_box[x] ^ s_box[y]] += 1

    # Construct DNF of all valid trails
    trails = []

    # All zero trail with probability 1
    for input_diff in range(16):
        for output_diff in range(16):
            if ddt[input_diff][output_diff] != 0:
                tmp = []
                tmp.append((input_diff >> 3) & 1)
                tmp.append((input_diff >> 2) & 1)
                tmp.append((input_diff >> 1) & 1)
                tmp.append((input_diff >> 0) & 1)
                tmp.append((output_diff >> 3) & 1)
                tmp.append((output_diff >> 2) & 1)
                tmp.append((output_diff >> 1) & 1)
                tmp.append((output_diff >> 0) & 1)
                if ddt[input_diff][output_diff] == 2:
                    tmp += [0, 1, 1, 1]  # 2^-3
                elif ddt[input_diff][output_diff] == 4:
                    tmp += [0, 0, 1, 1]  # 2^-2
                elif ddt[input_diff][output_diff] == 8:
                    tmp += [0, 0, 0, 1]  # 2^-1
                elif ddt[input_diff][output_diff] == 16:
                    tmp += [0, 0, 0, 0]
                trails.append(tmp)
    return trails


def add4bitSbox(s_box_trails, left_in, s_out, w, indexes):
    """
    Adds the constraints for the S-box and the weight
    for the differential transition.

    sbox is a list representing the S-box.

    variables should be a list containing the input and
    output variables of the S-box and the weight variables.

    S(x) = y

    The probability of the transitions is
    2^-{hw(w0||w1||w2||w3)}

    w ... hamming weight from the DDT table
    """

    variables = ["{0}[{1}:{1}]".format(left_in, indexes[3]),
                 "{0}[{1}:{1}]".format(left_in, indexes[2]),
                 "{0}[{1}:{1}]".format(left_in, indexes[1]),
                 "{0}[{1}:{1}]".format(left_in, indexes[0]),
                 "{0}[{1}:{1}]".format(s_out, indexes[3]),
                 "{0}[{1}:{1}]".format(s_out, indexes[2]),
                 "{0}[{1}:{1}]".format(s_out, indexes[1]),
                 "{0}[{1}:{1}]".format(s_out, indexes[0]),
                 "{0}[{1}:{1}]".format(w, indexes[3]),
                 "{0}[{1}:{1}]".format(w, indexes[2]),
                 "{0}[{1}:{1}]".format(w, indexes[1]),
                 "{0}[{1}:{1}]".format(w, indexes[0])]

    cnf = []
    for valid_trail in s_box_trails:
        c = []
        for i in range(len(variables)):
            # c.append("({}=0bin{})".format(variables[i], valid_trail[i]))
            c.append("BVXOR({0},0bin{1})".format(variables[i], valid_trail[i]))
        # cnf.append("(" + "&".join(c) + ")")
        cnf.append("&".join(c))
        # cnf.append("(" + "&".join(c) + ")")
        break

    conditions = "|".join(cnf)

    command = "ASSERT({0}=0bin1);\n".format(conditions)

    return command

    # # Build CNF from invalid trails
    # cnf = ""
    # for prod in itertools.product([0, 1], repeat=len(s_box_trails[0])):
    #     # Trail is not valid
    #     if list(prod) not in s_box_trails:
    #         expr = ["~" if x == 1 else "" for x in list(prod)]
    #         clause = ""
    #         for literal in range(12):
    #             clause += "{0}{1} | ".format(expr[literal], variables[literal])
    #
    #         cnf += "({}) &".format(clause[:-2])
    #
    # return "ASSERT({} = 0bin1);\n".format(cnf[:-2])
