from ciphers.cipher import AbstractCipher
from parser import stpcommands
import util


class Sand(AbstractCipher):
    name = 'sand'

    alpha = 0

    beta = 1

    def createSTP(self, filename, parameters):
        word_size = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]
        switch_start_round = parameters["switchStartRound"]
        switch_rounds = parameters["switchRounds"]

        block_size = word_size // 2

        with open(filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Sand{} w={} Rounds={}\n\n\n".format(word_size, weight,
                                                                                   rounds))
            stp_file.write(header)
            command = ""
            xl, xr, yl, yr, and_out, and_out_1, and_out_2, and_out_3, and_out_4, and_m, f_m, w = initial_file(rounds,
                                                                                                              block_size,
                                                                                                              weight,
                                                                                                              stp_file)

            for i in range(rounds):
                self.setup_round(stp_file, xl[i], xr[i], xl[i + 1], xr[i + 1], and_out[i], and_out_1[i],
                                 and_out_2[i], and_out_3[i], and_out_4[i], and_m[i], f_m[i],
                                 w[i], block_size)

            command += self.pre_handle(parameters)
            stp_file.write(command)
            #stpcommands.assertNonZero(stp_file, [xl[0]], block_size)

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            stpcommands.setupQuery(stp_file)


    def setup_round(self, stp_file, in_left, in_right, out_left, out_right, and_out, and_out_1, and_out_2, and_out_3,
                    and_out_4, a_res, f_res, w,
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

        and_matrix = util.sand_t(block_size)

        g_0_matrix = util.sand_t(block_size, self.alpha)

        # # G_0
        group_num = block_size // 4
        for i in range(block_size // 4):
            command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]|{4}[{5}:{5}]);\n".format(a_res, and_matrix[3][i], in_left,
                                                                                  g_0_matrix[0][i],
                                                                                  in_left, g_0_matrix[1][i])
            command += "ASSERT(BVLE({0}[{1}:{1}], {2}[{3}:{3}]));\n".format(f_res, and_matrix[3][i], a_res,
                                                                            and_matrix[3][i])
            command += ("ASSERT({0}[{1}:{1}] = BVXOR({2}[{3}:{3}],{4}[{5}:{5}]));\n"
                        .format(and_out, and_matrix[3][i],
                                f_res, and_matrix[3][i],
                                in_left, g_0_matrix[3][i]))

            command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]|{4}[{5}:{5}]);\n".format(a_res, and_matrix[0][i], and_out,
                                                                                  and_matrix[3][i],
                                                                                  in_left, g_0_matrix[2][i])
            command += "ASSERT(BVLE({0}[{1}:{1}], {2}[{3}:{3}]));\n".format(f_res, and_matrix[0][i], a_res,
                                                                            and_matrix[0][i])
            command += ("ASSERT({0}[{1}:{1}] = BVXOR({2}[{3}:{3}],{4}[{5}:{5}]));\n"
                        .format(and_out, and_matrix[0][i],
                                f_res, and_matrix[0][i],
                                in_left, g_0_matrix[0][i]))
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(and_out, and_matrix[1][i]
                                                                       , in_left, g_0_matrix[1][i])
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(and_out, and_matrix[2][i]
                                                                       , in_left, g_0_matrix[2][i])

        and_matrix_1 = util.sand_t(block_size)
        g_1_matrix = util.sand_t(block_size, self.beta)
        # G_1
        for i in range(block_size // 4):
            command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]|{4}[{5}:{5}]);\n".format(a_res, group_num * 1 + i, in_left,
                                                                                  g_1_matrix[0][i],
                                                                                  in_left, g_1_matrix[2][i])
            command += "ASSERT(BVLE({0}[{1}:{1}], {2}[{3}:{3}]));\n".format(f_res, group_num * 1 + i, a_res,
                                                                            group_num * 1 + i)
            command += ("ASSERT({0}[{1}:{1}] = BVXOR({2}[{3}:{3}],{4}[{5}:{5}]));\n"
                        .format(and_out_1, and_matrix_1[1][i],
                                f_res, group_num * 1 + i,
                                in_left, g_1_matrix[1][i]))

            command += "ASSERT({0}[{1}:{1}]={2}[{3}:{3}]|{4}[{5}:{5}]);\n".format(a_res, group_num * 2 + i, and_out_1,
                                                                                  and_matrix_1[1][i],
                                                                                  in_left, g_1_matrix[3][i])
            command += "ASSERT(BVLE({0}[{1}:{1}], {2}[{3}:{3}]));\n".format(f_res, group_num * 2 + i, a_res,
                                                                            group_num * 2 + i)
            command += ("ASSERT({0}[{1}:{1}] = BVXOR({2}[{3}:{3}],{4}[{5}:{5}]));\n"
                        .format(and_out_1, and_matrix_1[2][i],
                                f_res, group_num * 2 + i,
                                in_left, g_1_matrix[2][i]))

            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(and_out_1, and_matrix_1[0][i]
                                                                       , in_left, g_1_matrix[0][i])
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(and_out_1, and_matrix_1[3][i]
                                                                       , in_left, g_1_matrix[3][i])

        command += "ASSERT({0} = BVXOR({1},{2}));\n".format(and_out_2, and_out, and_out_1)
        #
        and_matrix_2 = util.sand_t(block_size)
        and_out_3_matrix = util.sand_t(block_size)
        if block_size == 32:
            for i in range(block_size // 8):
                for j, k in enumerate([7, 4, 1, 6, 3, 0, 5, 2]):
                    command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(and_out_3, and_out_3_matrix[i][k],
                                                                               and_out_2, and_matrix_2[i][j])
        command += ("ASSERT({0} = BVXOR({1},{2}));\n".format(out_left, in_right, and_out_3))

        a_list = []
        for i in range(block_size):
            t = '0bin' + '0' * 31 + "@{0}[{1}:{1}]".format(a_res, i)
            a_list.append(t)

        command += "ASSERT({0}=BVPLUS({1},".format(w, block_size) + ",".join(a_list) + "));\n"

        stp_file.write(command)

    def getFormatString(self):
        return ['XL', 'XR', 'YL', 'YR', 'AAND', 'BAND', 'CAND', 'DAND', 'w']

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


def initial_file(rounds, block_size, weight, stp_file):
    xl = ["XL{}".format(i) for i in range(rounds + 1)]
    xr = ["XR{}".format(i) for i in range(rounds + 1)]
    yl = ["YL{}".format(i) for i in range(rounds + 1)]
    yr = ["YR{}".format(i) for i in range(rounds + 1)]
    and_out = ["AAND{}".format(i) for i in range(rounds + 1)]
    and_out_1 = ["BAND{}".format(i) for i in range(rounds + 1)]
    and_out_2 = ["CAND{}".format(i) for i in range(rounds + 1)]
    and_out_3 = ["DAND{}".format(i) for i in range(rounds + 1)]
    and_out_4 = ["EAND{}".format(i) for i in range(rounds + 1)]
    and_me = ["ANDM{}".format(i) for i in range(rounds + 1)]
    f_me = ["FME{}".format(i) for i in range(rounds + 1)]
    w = ["w{}".format(i) for i in range(rounds)]

    stpcommands.setupVariables(stp_file, xl, block_size)
    stpcommands.setupVariables(stp_file, xr, block_size)
    stpcommands.setupVariables(stp_file, yl, block_size)
    stpcommands.setupVariables(stp_file, yr, block_size)
    stpcommands.setupVariables(stp_file, and_out, block_size)
    stpcommands.setupVariables(stp_file, and_out_1, block_size)
    stpcommands.setupVariables(stp_file, and_out_2, block_size)
    stpcommands.setupVariables(stp_file, and_out_3, block_size)
    stpcommands.setupVariables(stp_file, and_out_4, block_size)
    stpcommands.setupVariables(stp_file, and_me, block_size)
    stpcommands.setupVariables(stp_file, f_me, block_size)
    stpcommands.setupVariables(stp_file, w, block_size)

    stpcommands.setupWeightComputation(stp_file, weight, w, block_size)

    return xl, xr, yl, yr, and_out, and_out_1, and_out_2, and_out_3, and_out_4, and_me, f_me, w
