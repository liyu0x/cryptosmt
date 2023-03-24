'''
Created on May 10, 2022

@author: jesenteh
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class katan(AbstractCipher):
    """
    Represents the differential behaviour of Katan32 and can be used
    to find differential characteristics for the given parameters.
    It uses an alternative representation of Katan32 in ARX form.
    """

    name = "katan"

    katan_32_specification = {"L1": 13, "L2": 19, "x1": 12, "x2": 7, "x3": 8, "x4": 5, "x5": 3, "y1": 18, "y2": 7,
                              "y3": 12, "y4": 10, "y5": 8, "y6": 3}

    katan_48_specification = {"L1": 19, "L2": 29, "x1": 18, "x2": 12, "x3": 15, "x4": 7, "x5": 6, "y1": 28, "y2": 19,
                              "y3": 21, "y4": 13, "y5": 15, "y6": 6}

    katan_64_specification = {"L1": 25, "L2": 39, "x1": 24, "x2": 15, "x3": 20, "x4": 11, "x5": 9, "y1": 38, "y2": 25,
                              "y3": 33, "y4": 21, "y5": 14, "y6": 9}

    katan_sepecification = None

    BCT_INPUT_SIZE = 4

    x_register_indexes = ["y3", "y4", "y5", "y6"]
    x_non_linear_register = []
    y_register_indexes = ["x3", "x4"]
    y_non_linear_register = []

    IR = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0,
          1, 1, 0, 1, 0, 1, 0, 1, 0, 1,
          1, 1, 1, 0, 1, 1, 0, 0, 1, 1,
          0, 0, 1, 0, 1, 0, 0, 1, 0, 0,
          0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
          1, 1, 1, 1, 0, 0, 0, 0, 1, 0,
          0, 0, 0, 1, 0, 1, 0, 0, 0, 0,
          0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
          1, 1, 1, 1, 0, 1, 0, 1, 0, 0,
          0, 1, 0, 1, 0, 1, 0, 0, 1, 1,
          0, 0, 0, 0, 1, 1, 0, 0, 1, 1,
          1, 0, 1, 1, 1, 1, 1, 0, 1, 1,
          1, 0, 1, 0, 0, 1, 0, 1, 0, 1,
          1, 0, 1, 0, 0, 1, 1, 1, 0, 0,
          1, 1, 0, 1, 1, 0, 0, 0, 1, 0,
          1, 1, 1, 0, 1, 1, 0, 1, 1, 1,
          1, 0, 0, 1, 0, 1, 1, 0, 1, 1,
          0, 1, 0, 1, 1, 1, 0, 0, 1, 0,
          0, 1, 0, 0, 1, 1, 0, 1, 0, 0,
          0, 1, 1, 1, 0, 0, 0, 1, 0, 0,
          1, 1, 1, 1, 0, 1, 0, 0, 0, 0,
          1, 1, 1, 0, 1, 0, 1, 1, 0, 0,
          0, 0, 0, 1, 0, 1, 1, 0, 0, 1,
          0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
          1, 1, 0, 0, 0, 0, 0, 0, 0, 1,
          0, 0, 1, 0]

    def prepare(self, worksize):
        if worksize == 32:
            self.katan_sepecification = self.katan_32_specification
        elif worksize == 48:
            self.katan_sepecification = self.katan_48_specification
        else:
            self.katan_sepecification = self.katan_64_specification

        for x in self.x_register_indexes:
            self.x_non_linear_register.append(self.katan_sepecification[x])
        for y in self.y_register_indexes:
            self.y_non_linear_register.append(self.katan_sepecification[y])

    def ax_box(self, x):
        x0 = x >> 3 & 0x1
        x1 = x >> 2 & 0x1
        x2 = x >> 1 & 0x1
        x3 = x & 0x1
        return (x0 & x1) ^ (x2 & x3)

    def ax_box_2(self, x):
        x0 = x >> 1 & 0x1
        x1 = x & 0x1
        return x0 & x1

    def getSbox(self):
        return None

    def getSboxSize(self):
        return 4

    def getDesign(self):
        return "ax"

    def getPerm(self):
        return None

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X', 'Y', 'A', 'F', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for KATAN32 with
        the given parameters.
        """
        mode = parameters["mode"]
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]
        offset = parameters["offset"]
        switch_start_round = parameters["switchStartRound"]
        switch_rounds = parameters["switchRounds"]

        self.prepare(wordsize)

        e0_search_rounds = rounds if switch_start_round == -1 else switch_start_round
        em_search_rounds = rounds if switch_start_round == -1 else e0_search_rounds + switch_rounds
        e1_search_rounds = rounds

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% KATAN32 w={}"
                      "rounds={} with IR offset={}\n\n\n".format(wordsize, rounds, offset))
            stp_file.write(header)

            # Setup variables
            # x = input (32), f = outputs of AND operation (Only 3 bits required, use 3 bits to store)
            # a = active or inactive AND operation (Only 3 bits required, use 3 bits to store)
            x = ["X{}".format(i) for i in range(rounds + 1)]
            y = ["Y{}".format(i) for i in range(rounds + 1)]
            f = ["F{}".format(i) for i in range(rounds)]
            a = ["A{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, f, wordsize)
            stpcommands.setupVariables(stp_file, a, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            # Modify start_round to start from different positions

            # E0
            for i in range(e0_search_rounds):
                self.setupKatanRound(stp_file, x[i], f[i], a[i], x[i + 1],
                                     w[i], wordsize, i, offset, False)
            for i in range(e0_search_rounds, em_search_rounds - 1):
                self.setupKatanRound(stp_file, x[i], f[i], a[i], x[i + 1],
                                     w[i], wordsize, i, offset, True)
            # Em
            for i in range(e0_search_rounds, em_search_rounds):
                command = stpcommands.and_bct(self.small_vari(x[i], y[i], 0), self.ax_box_2, 2)
                command += stpcommands.and_bct(self.big_vari(x[i], y[i], 0), self.ax_box, 4)
                if wordsize >= 48:
                    command += stpcommands.and_bct(self.small_vari(x[i], y[i], 1), self.ax_box_2, 2)
                    command += stpcommands.and_bct(self.big_vari(x[i], y[i], 1), self.ax_box, 4)
                if wordsize >= 64:
                    command += stpcommands.and_bct(self.small_vari(x[i], y[i], 2), self.ax_box_2, 2)
                    command += stpcommands.and_bct(self.big_vari(x[i], y[i], 2), self.ax_box, 4)
                stp_file.write(command)
            # E1
            for i in range(e0_search_rounds, em_search_rounds):
                self.setupKatanRound(stp_file, y[i], f[i], a[i], y[i + 1],
                                     w[i], wordsize, i, offset, True)
            for i in range(em_search_rounds, e1_search_rounds):
                self.setupKatanRound(stp_file, y[i], f[i], a[i], y[i + 1],
                                     w[i], wordsize, i, offset, False)

            if switch_start_round == -1:
                stpcommands.assertNonZero(stp_file, x, wordsize)
            else:
                # use BCT
                stpcommands.assertNonZero(stp_file, x[0:em_search_rounds - 1], wordsize)
                stpcommands.assertNonZero(stp_file, y[em_search_rounds:rounds + 1], wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupKatanRound(self, stp_file, x_in, f, a, x_out, w, wordsize, r, offset, enable_bct):
        """
        Model for differential behaviour of one round KATAN32
        """
        command = ""

        # Check if AND is active
        # a[0]=x[y5]|x[y6]
        command += "ASSERT({0}[0:0] = {1}[{2}:{2}]|{3}[{4}:{4}]);\n".format(a, x_in, self.katan_sepecification["y5"],
                                                                            x_in, self.katan_sepecification["y6"])
        # a[1] = x[y3]| x[y4]
        command += "ASSERT({0}[1:1] = {1}[{2}:{2}]|{3}[{4}:{4}]);\n".format(a, x_in, self.katan_sepecification["y3"],
                                                                            x_in, self.katan_sepecification["y4"])
        # Locations for L1 = 5 and 8. In full 32-bit register, 5+19 = 24, 8+19 = 27
        # a[2] = x[x3+L2] | x[x4+L2]
        command += "ASSERT({0}[2:2] = {1}[{2}:{2}]|{3}[{4}:{4}]);\n".format(a, x_in, self.katan_sepecification["x3"] +
                                                                            self.katan_sepecification["L2"], x_in,
                                                                            self.katan_sepecification["x4"] +
                                                                            self.katan_sepecification["L2"])

        if wordsize >= 48:
            # Check if AND is active
            # a[0]=x[y5]|x[y6]
            command += "ASSERT({0}[3:3] = {1}[{2}:{2}]|{3}[{4}:{4}]);\n".format(a, x_in,
                                                                                self.katan_sepecification["y5"] - 1,
                                                                                x_in,
                                                                                self.katan_sepecification["y6"] - 1)
            # a[1] = x[y3]| x[y4]
            command += "ASSERT({0}[4:4] = {1}[{2}:{2}]|{3}[{4}:{4}]);\n".format(a, x_in,
                                                                                self.katan_sepecification["y3"] - 1,
                                                                                x_in,
                                                                                self.katan_sepecification["y4"] - 1)
            # Locations for L1 = 5 and 8. In full 32-bit register, 5+19 = 24, 8+19 = 27
            # a[2] = x[x3+L2] | x[x4+L2]
            command += "ASSERT({0}[5:5] = {1}[{2}:{2}]|{3}[{4}:{4}]);\n".format(a, x_in,
                                                                                self.katan_sepecification["x3"] +
                                                                                self.katan_sepecification["L2"] - 1,
                                                                                x_in,
                                                                                self.katan_sepecification["x4"] +
                                                                                self.katan_sepecification["L2"] - 1)

        if wordsize >= 64:
            # Check if AND is active
            # a[0]=x[y5]|x[y6]
            command += "ASSERT({0}[6:6] = {1}[{2}:{2}]|{3}[{4}:{4}]);\n".format(a, x_in,
                                                                                self.katan_sepecification["y5"] - 2,
                                                                                x_in,
                                                                                self.katan_sepecification["y6"] - 2)
            # a[1] = x[y3]| x[y4]
            command += "ASSERT({0}[7:7] = {1}[{2}:{2}]|{3}[{4}:{4}]);\n".format(a, x_in,
                                                                                self.katan_sepecification["y3"] - 2,
                                                                                x_in,
                                                                                self.katan_sepecification["y4"] - 2)
            # Locations for L1 = 5 and 8. In full 32-bit register, 5+19 = 24, 8+19 = 27
            # a[2] = x[x3+L2] | x[x4+L2]
            command += "ASSERT({0}[8:8] = {1}[{2}:{2}]|{3}[{4}:{4}]);\n".format(a, x_in,
                                                                                self.katan_sepecification["x3"] +
                                                                                self.katan_sepecification["L2"] - 2,
                                                                                x_in,
                                                                                self.katan_sepecification["x4"] +
                                                                                self.katan_sepecification["L2"] - 2)

        if enable_bct:
            # set zero to both weight
            command += "ASSERT({0}[1:1] = 0b0);\n".format(w, a)  # AND in the L1 register
            command += "ASSERT({0}[0:0] = 0b0);\n".format(w, a)
        else:
            # w[1]=a[2]
            command += "ASSERT({0}[1:1] = {1}[2:2]);\n".format(w, a)  # AND in the L1 register
            # As long as either 1 AND operation in L2 register is active, prob is 1
            # w[0]=a[0]|a[1]
            command += "ASSERT({0}[0:0] = {1}[0:0] | {1}[1:1]);\n".format(w, a)
            if wordsize >= 48:
                command += "ASSERT({0}[3:3] = {1}[5:5]);\n".format(w, a)
                command += "ASSERT({0}[2:2] = {1}[3:3] | {1}[4:4]);\n".format(w, a)
            if wordsize >= 64:
                command += "ASSERT({0}[3:3] = {1}[8:8]);\n".format(w, a)
                command += "ASSERT({0}[2:2] = {1}[6:6] | {1}[7:7]);\n".format(w, a)

        for i in range(3):
            command += "ASSERT(BVLE({0}[{2}:{2}],{1}[{2}:{2}]));\n".format(f, a, i)

        l2 = self.katan_sepecification["L2"]

        times = 1
        if wordsize == 48:
            times = 2
        elif wordsize == 64:
            times = 3
        for i in range(times):
            # Permutation layer (shift left L2 by 1 except for position 18)
            for i in range(0, l2 - 1):
                command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(x_out, i + 1, x_in, i)
            # Permutation layer (shift left L1 by 1 except for position 31 (L1_12))
            for i in range(l2, wordsize - 1):
                command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(x_out, i + 1, x_in, i)

            # Perform XOR operation for to get bits for position L2_0 and 19 (L1_0)
            # x_out[0] = x[31]^x[26]^a[2]^(x[22]&IR[r])
            command += "ASSERT({0}[0:0] = BVXOR({1}[{2}:{2}],BVXOR({1}[{3}:{3}],BVXOR({4}[2:2],({1}[{5}:{5}]&0b{6})))));\n".format(
                x_out,
                x_in,
                l2 + self.katan_sepecification["x1"],
                l2 + self.katan_sepecification["x2"],
                f,
                l2 + self.katan_sepecification["x5"],
                self.IR[r + offset])
            # x_out[19] = x[18]^a[1]^x[7]^a[0]

            command += "ASSERT({0}[{1}:{1}] = BVXOR({2}[{3}:{3}],BVXOR({4}[1:1],BVXOR({2}[{5}:{5}],{4}[0:0]))));\n".format(
                x_out,
                l2,
                x_in,
                self.katan_sepecification["y1"],
                f,
                self.katan_sepecification["y2"])

        # zeros = "0b"
        # for i in range(wordsize - 3):
        #     zeros += "0"
        # command += "ASSERT({0} = {1}[{2}:3]);\n".format(zeros, f, wordsize - 1)
        # command += "ASSERT({0} = {1}[{2}:3]);\n".format(zeros, a, wordsize - 1)
        # zeros += "0"
        # command += "ASSERT({0} = {1}[{2}:2]);\n".format(zeros,
        #                                                 w, wordsize - 1)  # Use 2 bits to store would be sufficient

        stp_file.write(command)
        return

    def small_vari(self, x_in, x_out, offset):
        l2 = self.katan_sepecification["L2"]
        variables = ["{0}[{1}:{1}]".format(x_in, l2 + self.katan_sepecification["x3"] - offset),
                     "{0}[{1}:{1}]".format(x_in, l2 + self.katan_sepecification["x4"] - offset),
                     "{0}[{1}:{1}]".format(x_out, l2 + self.katan_sepecification["x3"] - offset + 1),
                     "{0}[{1}:{1}]".format(x_out, l2 + self.katan_sepecification["x4"] - offset + 1)]
        return variables

    def big_vari(self, x_in, x_out, offset):
        variables = ["{0}[{1}:{1}]".format(x_in, self.katan_sepecification["y3"] - offset),
                     "{0}[{1}:{1}]".format(x_in, self.katan_sepecification["y4"] - offset),
                     "{0}[{1}:{1}]".format(x_in, self.katan_sepecification["y5"] - offset),
                     "{0}[{1}:{1}]".format(x_in, self.katan_sepecification["y6"] - offset),
                     "{0}[{1}:{1}]".format(x_out, self.katan_sepecification["y3"] - offset + 1),
                     "{0}[{1}:{1}]".format(x_out, self.katan_sepecification["y4"] - offset + 1),
                     "{0}[{1}:{1}]".format(x_out, self.katan_sepecification["y5"] - offset + 1),
                     "{0}[{1}:{1}]".format(x_out, self.katan_sepecification["y6"] - offset + 1)]

        return variables
