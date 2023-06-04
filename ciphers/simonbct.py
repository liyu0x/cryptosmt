'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
import itertools
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl


class SimonCipher(AbstractCipher):
    """
    Represents the differential behaviour of SIMON and can be used
    to find differential characteristics for the given parameters.
    """

    name = "simon"
    rot_alpha = 8
    rot_beta = 1
    rot_gamma = 2

    def left_rotate_array(self, arr, n):
        n = n % len(arr)
        return arr[n:] + arr[:n]

    def non_linear_part(self, x):
        x0 = x >> 1 & 0x1
        x1 = x & 0x1
        return x0 & x1

    def bct_vari(self, x_in, x_out, word_size):
        ori = [i for i in range(word_size)]
        alpha_vari = self.left_rotate_array(ori, self.rot_alpha)
        beta_vari = self.left_rotate_array(ori, self.rot_beta)
        variables = []
        for i in range(word_size):
            variable = ["{0}[{1}:{1}]".format(x_in, alpha_vari[i]),
                        "{0}[{1}:{1}]".format(x_in, beta_vari[i]),
                        "{0}[{1}:{1}]".format(x_out, alpha_vari[i]),
                        "{0}[{1}:{1}]".format(x_out, beta_vari[i])]
            variables.append(variable)

        return variables

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['XL', 'XR', 'YL', 'YR', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for SIMON with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]
        switch_start_round = parameters["switchStartRound"]
        switch_rounds = parameters["switchRounds"]

        e0_start_search_num = 0
        e0_end_search_num = rounds if switch_start_round == -1 else switch_start_round
        em_start_search_num = rounds if switch_start_round == -1 else switch_start_round
        em_end_search_num = rounds if switch_start_round == -1 else em_start_search_num + switch_rounds
        e1_start_search_num = rounds if switch_start_round == -1 else switch_start_round + switch_rounds
        e1_end_search_num = rounds

        # Replace with custom if set in parameters.
        if "rotationconstants" in parameters:
            self.rot_alpha = parameters["rotationconstants"][0]
            self.rot_beta = parameters["rotationconstants"][1]
            self.rot_gamma = parameters["rotationconstants"][2]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Simon w={} alpha={} beta={}"
                      " gamma={} rounds={}\n\n\n".format(wordsize,
                                                         self.rot_alpha,
                                                         self.rot_beta,
                                                         self.rot_gamma,
                                                         rounds))
            stp_file.write(header)
            command = ""
            # Setup variables
            # x = left, y = right
            xl = ["XL{}".format(i) for i in range(rounds + 1)]
            xr = ["XR{}".format(i) for i in range(rounds + 1)]
            yl = ["YL{}".format(i) for i in range(rounds + 1)]
            yr = ["YR{}".format(i) for i in range(rounds + 1)]

            and_out = ["andout{}".format(i) for i in range(rounds + 1)]

            and_out_t = ["andoutt{}".format(i) for i in range(rounds + 1)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, xl, wordsize)
            stpcommands.setupVariables(stp_file, xr, wordsize)
            stpcommands.setupVariables(stp_file, yl, wordsize)
            stpcommands.setupVariables(stp_file, yr, wordsize)
            stpcommands.setupVariables(stp_file, and_out, wordsize)
            stpcommands.setupVariables(stp_file, and_out_t, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)
            
            # E0
            for i in range(e0_start_search_num, e0_end_search_num):
                self.setupSimonRound(stp_file, xl[i], xr[i], xl[i + 1], xr[i + 1],
                                     and_out[i], w[i], wordsize)
            # Em
            for i in range(em_start_search_num, em_end_search_num):
                variable_arr = self.bct_vari(xl[i], yr[i + 1], wordsize)
                command += self.and_bct(variable_arr, self.non_linear_part, 2)
                self.setupSimonRound(stp_file, xl[i], xr[i], yl[i + 1], yr[i + 1],
                                     and_out[i], w[i], wordsize, True)
                #variable_arr = self.bct_vari(xl[i-1], yl[i + 1], wordsize)
                #command += self.and_bct(variable_arr, self.non_linear_part, 2)
                #command += "ASSERT(NOT({}={}));\n".format(yl[i+1], "0x0000")
                #command += "ASSERT({}={});\n".format(yl[i+1], x)

            # E1
            for i in range(e1_start_search_num, e1_end_search_num):
                self.setupSimonRound(stp_file, yl[i], yr[i], yl[i + 1], yr[i + 1],
                                     and_out[i], w[i], wordsize)

            #No all zero characteristic
            if switch_start_round == -1:
                stpcommands.assertNonZero(stp_file, xl + xr, wordsize)
            else:
                # for i in range(e0_start_search_num,em_end_search_num+1):
                #     stpcommands.assertNonZero(stp_file,[xl[i]],wordsize)
                #     stpcommands.assertNonZero(stp_file,[xr[i]],wordsize)
                # use BCT
                stpcommands.assertNonZero(stp_file, xl[e0_start_search_num:em_end_search_num], wordsize)
                stpcommands.assertNonZero(stp_file, xr[e0_start_search_num:em_end_search_num], wordsize)
                stpcommands.assertNonZero(stp_file, yl[em_start_search_num+1:e1_end_search_num], wordsize)
                stpcommands.assertNonZero(stp_file, yr[em_start_search_num+1:e1_end_search_num], wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, xl[0], xl[rounds])
                stpcommands.assertVariableValue(stp_file, xr[0], xr[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)
            stp_file.write(command)
            stpcommands.setupQuery(stp_file)

        return

    def setupSimonRound(self, stp_file, x_in, y_in, x_out, y_out, and_out, w,
                        wordsize, switch=False):
        """
        Model for differential behaviour of one round SIMON
        y[i+1] = x[i]
        x[i+1] = (x[i] <<< 1) & (x[i] <<< 8) ^ y[i] ^ (x[i] << 2)

        This model is only correct if gcd(self.rot_alpha - self.rot_beta, wordsize) = 1
        and self.rot_alpha > self.rot_beta
        """
        command = ""

        # Assert(y_out = x_in)
        command += "ASSERT({} = {});\n".format(y_out, x_in)

        x_in_rotalpha = rotl(x_in, self.rot_alpha, wordsize)
        x_in_rotbeta = rotl(x_in, self.rot_beta, wordsize)

        # Deal with dependent inputs
        varibits = "({0} | {1})".format(x_in_rotalpha, x_in_rotbeta)

        doublebits = self.getDoubleBits(x_in, wordsize)

        # Check for valid difference
        firstcheck = "({} & ~{})".format(and_out, varibits)
        secondcheck = "(BVXOR({}, {}) & {})".format(
            and_out, rotl(and_out, self.rot_alpha - self.rot_beta, wordsize), doublebits)
        thirdcheck = "(IF {0} = 0x{1} THEN BVMOD({2}, {3}, 0x{4}2) ELSE 0x{5} ENDIF)".format(
            x_in, "f" * (wordsize // 4), wordsize, and_out, "0" * (wordsize // 4 - 1),
                  "0" * (wordsize // 4))

        command += "ASSERT(({} | {} | {}) = 0x{});\n".format(
            firstcheck, secondcheck, thirdcheck, "0" * (wordsize // 4))

        # Assert XORs
        command += "ASSERT({} = BVXOR({}, BVXOR({}, {})));\n".format(
            x_out, rotl(x_in, self.rot_gamma, wordsize), y_in, and_out)

        if not switch:
        # Weight computation
            command += "ASSERT({0} = (IF {1} = 0x{4} THEN BVSUB({5},0x{4},0x{6}1) \
                        ELSE BVXOR({2}, {3}) ENDIF));\n".format(
                w, x_in, varibits, doublebits, "f" * (wordsize // 4),
                wordsize, "0" * ((wordsize // 4) - 1))

        stp_file.write(command)
        return

    def getDoubleBits(self, x_in, wordsize):
        command = "({0} & ~{1} & {2})".format(
            rotl(x_in, self.rot_beta, wordsize),
            rotl(x_in, self.rot_alpha, wordsize),
            rotl(x_in, 2 * self.rot_alpha - self.rot_beta, wordsize))
        return command

    def and_bct(self, variables_arr, non_part, input_size):
        bits = input_size
        size = 2 ** bits

        # create ^bct
        bct = [[0] * size for i in range(size)]
        for delta_in in range(size):
            for delta_out in range(size):
                for x in range(size):
                    x_delta_in = x ^ delta_in
                    x_delta_out = x ^ delta_out
                    x_delta_in_out = x ^ delta_in ^ delta_out
                    r_x = non_part(x)
                    r_x_delta_in = non_part(x_delta_in)
                    r_x_delta_out = non_part(x_delta_out)
                    r_x_delta_in_out = non_part(x_delta_in_out)
                    if r_x ^ r_x_delta_in ^ r_x_delta_out ^ r_x_delta_in_out == 0:
                        bct[delta_in][delta_out] += 1

        # Construct DNF of all valid trails
        trails = []
        # All zero trail with probability 1
        for input_diff in range(size):
            for output_diff in range(size):
                if bct[input_diff][output_diff] != 0:
                    tmp = []
                    for i in range(bits - 1, -1, -1):
                        tmp.append((input_diff >> i) & 1)
                    for i in range(bits - 1, -1, -1):
                        tmp.append((output_diff >> i) & 1)
                    trails.append(tmp)
        # trails = trails[0:int(len(trails)/2)]
        # Build CNF from invalid trails
        cnf = ""
        for variables in variables_arr:
            for prod in itertools.product([0, 1], repeat=len(trails[0])):
                # Trail is not valid
                if list(prod) not in trails:
                    expr = ["~" if x == 1 else "" for x in list(prod)]
                    clause = ""
                    for literal in range(bits * 2):
                        clause += "{0}{1} | ".format(expr[literal], variables[literal])

                    cnf += "({}) &".format(clause[:-2])
        return "ASSERT({} = 0bin1);\n".format(cnf[:-2])
