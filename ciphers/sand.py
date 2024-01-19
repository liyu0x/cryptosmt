from ciphers.cipher import AbstractCipher
from parser import stpcommands
import util


class Sand(AbstractCipher):
    name = 'sand'

    alpha = 0

    beta = 1

    def createSTP(self, filename, parameters):
        word_size = parameters["wordsize"]
        rounds = parameters["rounds"] + 1
        weight = parameters["sweight"]
        switch_start_round = parameters["switchStartRound"]
        switch_rounds = parameters["switchRounds"]

        block_size = word_size // 2

        with open(filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Sand{} w={} Rounds={}\n\n\n".format(word_size, weight,
                                                                                   rounds))
            stp_file.write(header)
            command = ""
            xl, xr, yl, yr, g0_rot, g0_and_f, g0_and_out, g0_xor_out, g1_rot, g1_and_f, g1_and_out, g1_xor_out, g12_xor_out, perm_out, w = initial_file(
                rounds,
                block_size,
                weight,
                stp_file)

            # loading init diff
            self.pre_round(stp_file, xl[0], xr[0], xl[1], xr[1], block_size)

            for i in range(1, rounds):
                self.setup_round(stp_file, xl[i], xr[i], xl[i + 1], xr[i + 1], g0_rot[i], g0_and_f[i],
                                 g0_and_out[i], g0_xor_out[i], g1_rot[i], g1_and_f[i], g1_and_out[i],
                                 g1_xor_out[i], g12_xor_out[i], perm_out[i],
                                 w[i], block_size)

            command += self.pre_handle(parameters)
            stp_file.write(command)
            stpcommands.assertNonZero(stp_file, [xl[0], xr[0]], block_size)

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

    def setup_round(self, stp_file, in_left, in_right, out_left, out_right, g0_rot, g0_and_f, g0_and_out,
                    g0_xor_out, g1_rot, g1_and_f, g1_and_out,
                    g1_xor_out, g12_xor_out, perm_out, w,
                    block_size, switch=False):
        """
        out_right = in_left
        out_left = (P_n(G_0(x^r ≪ _{n/4} \alpha) ⊕ G_1(x^r ≪ _{n/4} \beta)) ⊕ y^r ⊕ sk^r
        (\alpha,\beta) = (0,1)

        G_0 = {                                             G_1 = {
            y{0} = x{3} and x{2} xor x{0}                       y{2} = x{3} and x{1} xor x{2}
            y{3} = y{0} and x{1} xor x{3}                       y{1} = y{2} and x{0} xor x{1}
            y{2} = x{2}                                         y{3} = x{3}
            y{1} = x{1}                                         y{0} = x{0}
        }
        """

        command = ""
        command += "ASSERT({} = {});\n".format(out_right, in_left)

        group_size = block_size // 4

        # G_0
        g0_rot_index = util.sand_rot(block_size, self.alpha)

        if self.alpha != 0:
            for i in range(block_size):
                command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]);\n".format(g0_rot, i, in_left, g0_rot_index[i])
        else:
            command += "ASSERT({0}={1});\n".format(g0_rot, in_left)

        for i in range(block_size // 4):
            # y{0} = x{3} and x{2} xor x{0}
            command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]|{4}[{5}:{5}]);\n".format(g0_and_f, 0 * group_size + i, g0_rot,
                                                                                  3 * group_size + i,
                                                                                  g0_rot, 2 * group_size + i)

            command += "ASSERT(BVLE({0}[{1}:{1}], {2}[{3}:{3}]));\n".format(g0_and_out, 0 * group_size + i, g0_and_f,
                                                                            0 * group_size + i)

            command += ("ASSERT({0}[{1}:{1}] = BVXOR({2}[{3}:{3}],{4}[{5}:{5}]));\n"
                        .format(g0_xor_out, 0 * group_size + i,
                                g0_and_out, 0 * group_size + i,
                                g0_rot, 0 * group_size + i))

            # y{3} = y{0} and x{1} xor x{3}
            command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]|{4}[{5}:{5}]);\n".format(g0_and_f, 3 * group_size + i,
                                                                                  g0_xor_out,
                                                                                  0 * group_size + i,
                                                                                  g0_rot, 1 * group_size + i)

            command += "ASSERT(BVLE({0}[{1}:{1}], {2}[{3}:{3}]));\n".format(g0_and_out, 3 * group_size + i, g0_and_f,
                                                                            3 * group_size + i)

            command += ("ASSERT({0}[{1}:{1}] = BVXOR({2}[{3}:{3}],{4}[{5}:{5}]));\n"
                        .format(g0_xor_out, 3 * group_size + i,
                                g0_and_out, 3 * group_size + i,
                                g0_rot, 3 * group_size + i))

            # y{2} = x{2}
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(g0_xor_out, 2 * group_size + i
                                                                       , g0_rot, 2 * group_size + i)

            # y{1} = x{1}
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(g0_xor_out, 1 * group_size + i
                                                                       , g0_rot, 1 * group_size + i)

        # G_1
        g1_rot_index = util.sand_rot(block_size, self.beta)

        if self.beta != 0:
            for i in range(block_size):
                command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]);\n".format(g1_rot, i, in_left, g1_rot_index[i])
        else:
            command += "ASSERT({0}={1});\n".format(g1_rot, in_left)

        # G_1
        for i in range(block_size // 4):
            # y{2} = x{3} and x{1} xor x{2}
            command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]|{4}[{5}:{5}]);\n".format(g1_and_f, 2 * group_size + i, g1_rot,
                                                                                  3 * group_size + i,
                                                                                  g1_rot, 1 * group_size + i)

            command += "ASSERT(BVLE({0}[{1}:{1}], {2}[{3}:{3}]));\n".format(g1_and_out, 2 * group_size + i, g1_and_f,
                                                                            2 * group_size + i)

            command += ("ASSERT({0}[{1}:{1}] = BVXOR({2}[{3}:{3}],{4}[{5}:{5}]));\n"
                        .format(g1_xor_out, 2 * group_size + i,
                                g1_and_out, 2 * group_size + i,
                                g1_rot, 2 * group_size + i))

            # y{1} = y{2} and x{0} xor x{1}
            command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]|{4}[{5}:{5}]);\n".format(g1_and_f, 1 * group_size + i,
                                                                                  g1_xor_out,
                                                                                  2 * group_size + i,
                                                                                  g1_rot, 1 * group_size + i)

            command += "ASSERT(BVLE({0}[{1}:{1}], {2}[{3}:{3}]));\n".format(g1_and_out, 1 * group_size + i, g1_and_f,
                                                                            1 * group_size + i)

            command += ("ASSERT({0}[{1}:{1}] = BVXOR({2}[{3}:{3}],{4}[{5}:{5}]));\n"
                        .format(g1_xor_out, 1 * group_size + i,
                                g1_and_out, 1 * group_size + i,
                                g1_rot, 1 * group_size + i))

            # y{3} = x{3}
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(g1_xor_out, 3 * group_size + i
                                                                       , g1_rot, 3 * group_size + i)

            # y{0} = x{0}
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(g1_xor_out, 0 * group_size + i
                                                                       , g1_rot, 0 * group_size + i)

        # G1 xor G2
        command += "ASSERT({0} = BVXOR({1},{2}));\n".format(g12_xor_out, g0_xor_out, g1_xor_out)

        # P_out
        if block_size == 32:
            for i in range(block_size // 8):
                for j, k in enumerate([7, 4, 1, 6, 3, 0, 5, 2]):
                    command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(perm_out, i * 8 + j,
                                                                               g12_xor_out, i * 8 + k)
        command += ("ASSERT({0} = BVXOR({1},{2}));\n".format(out_left, in_right, perm_out))

        # sum_w_i = stpcommands.getWeightString([g0_and_f, g1_and_f], block_size, 0, w)
        # sum_w_i += '\n'
        # command += sum_w_i

        a_list = []
        for i in range(block_size):
            t = '0bin' + '0' * 31 + "@{0}[{1}:{1}]".format(g0_and_f, i)
            a_list.append(t)
            t = '0bin' + '0' * 31 + "@{0}[{1}:{1}]".format(g1_and_f, i)
            a_list.append(t)

        command += "ASSERT({0}=BVPLUS({1},".format(w, block_size) + ",".join(a_list) + "));\n"

        stp_file.write(command)

    def create_cluster_parameters(self, parameters, characteristics):
        pass

    def get_diff_hex(self, parameters, characteristics):
        pass

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
                output_diff_l = trails_data[r][0]
                output_diff_r = trails_data[r][1]

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
        return ['XL', 'XR', 'AXOROUT', 'BXOROUT', 'ABXOROUT', 'POUT', 'w']


def initial_file(rounds, block_size, weight, stp_file):
    xl = ["XL{}".format(i) for i in range(rounds + 1)]
    xr = ["XR{}".format(i) for i in range(rounds + 1)]
    yl = ["YL{}".format(i) for i in range(rounds + 1)]
    yr = ["YR{}".format(i) for i in range(rounds + 1)]
    g0_rot = ["AROT{}".format(i) for i in range(rounds + 1)]
    g0_and_f = ["AANDF{}".format(i) for i in range(rounds + 1)]
    g0_and_out = ["AANDOUT{}".format(i) for i in range(rounds + 1)]
    g0_xor_out = ["AXOROUT{}".format(i) for i in range(rounds + 1)]
    g1_rot = ["BROT{}".format(i) for i in range(rounds + 1)]
    g1_and_f = ["BANDF{}".format(i) for i in range(rounds + 1)]
    g1_and_out = ["BANDOUT{}".format(i) for i in range(rounds + 1)]
    g1_xor_out = ["BXOROUT{}".format(i) for i in range(rounds + 1)]
    g12_xor_out = ["ABXOROUT{}".format(i) for i in range(rounds + 1)]
    perm_out = ["POUT{}".format(i) for i in range(rounds + 1)]
    w = ["w{}".format(i) for i in range(rounds)]

    stpcommands.setupVariables(stp_file, xl, block_size)
    stpcommands.setupVariables(stp_file, xr, block_size)
    stpcommands.setupVariables(stp_file, yl, block_size)
    stpcommands.setupVariables(stp_file, yr, block_size)
    stpcommands.setupVariables(stp_file, g0_rot, block_size)
    stpcommands.setupVariables(stp_file, g0_and_out, block_size)
    stpcommands.setupVariables(stp_file, g0_and_f, block_size)
    stpcommands.setupVariables(stp_file, g0_xor_out, block_size)
    stpcommands.setupVariables(stp_file, g1_rot, block_size)
    stpcommands.setupVariables(stp_file, g1_and_f, block_size)
    stpcommands.setupVariables(stp_file, g1_and_out, block_size)
    stpcommands.setupVariables(stp_file, g1_xor_out, block_size)
    stpcommands.setupVariables(stp_file, g12_xor_out, block_size)
    stpcommands.setupVariables(stp_file, perm_out, block_size)
    stpcommands.setupVariables(stp_file, w, block_size)

    stpcommands.setupWeightComputation(stp_file, weight, w, block_size)

    return xl, xr, yl, yr, g0_rot, g0_and_f, g0_and_out, g0_xor_out, g1_rot, g1_and_f, g1_and_out, g1_xor_out, g12_xor_out, perm_out, w
