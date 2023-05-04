'''
Created on May 10, 2022

@author: jesenteh
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class katan32(AbstractCipher):
    """
    Represents the differential behaviour of Katan32 and can be used
    to find differential characteristics for the given parameters.
    It uses an alternative representation of Katan32 in ARX form.
    """

    name = "katan32m"

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

    def small_vari(self, x_in, x_out):
        variables = ["{0}[{1}:{1}]".format(x_in, 19 + 5),
                     "{0}[{1}:{1}]".format(x_in, 19 + 8),
                     "{0}[{1}:{1}]".format(x_out, 19 + 5 + 1),
                     "{0}[{1}:{1}]".format(x_out, 19 + 8 + 1)]
        return variables

    def big_vari(self, x_in, x_out):
        variables = ["{0}[{1}:{1}]".format(x_in, 3),
                     "{0}[{1}:{1}]".format(x_in, 8),
                     "{0}[{1}:{1}]".format(x_in, 10),
                     "{0}[{1}:{1}]".format(x_in, 12),
                     "{0}[{1}:{1}]".format(x_out, 3 + 1),
                     "{0}[{1}:{1}]".format(x_out, 8 + 1),
                     "{0}[{1}:{1}]".format(x_out, 10 + 1),
                     "{0}[{1}:{1}]".format(x_out, 12 + 1)]

        return variables

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
        return ['X', 'XA', 'Y', 'YA', 'w']

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

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% KATAN32 w={}"
                      "rounds={} with IR offset={}\n\n\n".format(wordsize, rounds, offset))
            stp_file.write(header)

            # Setup variables
            # x = input (32), f = outputs of AND operation (Only 3 bits required, use 3 bits to store)
            # a = active or inactive AND operation (Only 3 bits required, use 3 bits to store)
            x = ["X{}".format(i) for i in range(rounds + 1)]
            y = ["Y{}".format(i) for i in range(rounds + 1)]
            xc = ["XC{}".format(i) for i in range(rounds + 1)]
            yc = ["YC{}".format(i) for i in range(rounds + 1)]
            xf = ["XF{}".format(i) for i in range(rounds)]
            xa = ["XA{}".format(i) for i in range(rounds)]
            yf = ["YF{}".format(i) for i in range(rounds)]
            ya = ["YA{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, xf, wordsize)
            stpcommands.setupVariables(stp_file, xa, wordsize)
            stpcommands.setupVariables(stp_file, yf, wordsize)
            stpcommands.setupVariables(stp_file, ya, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            command = ""
            for i in range(rounds):
                self.setupKatanRound(stp_file, x[i], xf[i], xa[i], x[i + 1], i, offset)
                self.setupKatanRound(stp_file, y[i], yf[i], ya[i], y[i + 1], i, offset)
                command += stpcommands.and_bct(self.small_vari(x[i], y[i]), self.ax_box_2, 2)
                command += stpcommands.and_bct(self.big_vari(x[i], y[i]), self.ax_box, 4)

                compute_weight(stp_file, x[i], y[i], xa[i], ya[i], xc[i], yc[i], w[i])

            stp_file.write(command)
            # COMPUTE OVERLAPPING
            # for i in range(rounds):
            #     self.compute_weight(stp_file, x[i], xa[i], xf[i], y[i], ya[i], yf[i], w[i], i)

            stpcommands.assertNonZero(stp_file, x, wordsize)
            stpcommands.assertNonZero(stp_file, y, wordsize)

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

    def setupKatanRound(self, stp_file, x_in, f, a, x_out, r, offset):
        command = ""

        # Check if AND is active
        # a[0] = x[3] | x[8]
        command += "ASSERT({0}[0:0] = {1}[3:3]|{2}[8:8]);\n".format(a, x_in, x_in)
        # a[1] = x[10]| x[12]
        command += "ASSERT({0}[1:1] = {1}[10:10]|{2}[12:12]);\n".format(a, x_in, x_in)
        # Locations for L1 = 5 and 8. In full 32-bit register, 5+19 = 24, 8+19 = 27
        # a[2] = x[24] | x[27]
        command += "ASSERT({0}[2:2] = {1}[24:24]|{2}[27:27]);\n".format(a, x_in, x_in)

        for i in range(3):
            command += "ASSERT(BVLE({0}[{2}:{2}],{1}[{2}:{2}]));\n".format(f, a, i)

        # Permutation layer (shift left L2 by 1 except for position 18)
        for i in range(0, 18):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(x_out, i + 1, x_in, i)
        # Permutation layer (shift left L1 by 1 except for position 31 (L1_12))
        for i in range(19, 31):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(x_out, i + 1, x_in, i)

        # Perform XOR operation for to get bits for position L2_0 and 19 (L1_0)
        # x_out[0] = x[31]^x[26]^a[2]^(x[22]&IR[r])
        command += "ASSERT({0}[0:0] = BVXOR({1}[31:31],BVXOR({1}[26:26],BVXOR({2}[2:2],({1}[22:22]&0b{3})))));\n".format(
            x_out, x_in, f, self.IR[r + offset])
        # x_out[19] = x[18]^a[1]^x[7]^a[0]
        command += "ASSERT({0}[19:19] = BVXOR({1}[18:18],BVXOR({2}[1:1],BVXOR({1}[7:7],{2}[0:0]))));\n".format(x_out,
                                                                                                               x_in, f)
        stp_file.write(command)
        return


def compute_weight(stp_file, x, y, xa, ya, xc, yc, w):
    command = ""

    command += "ASSERT({0}[0:0]={1}[2:2]&{2}[2:2]);\n".format(w, xa, ya)
    command += "ASSERT({0}[1:1]=BVXOR({1}[0:0],{1}[1:1])&BVXOR({2}[0:0],{2}[1:1]));\n".format(w, xa, ya)
    # command += "ASSERT({0}[1:1]={1}[1:1]&{2}[1:1]);\n".format(w, xa, ya)
    # command += "ASSERT({0}[2:2]={1}[0:0]&{2}[0:0]);\n".format(w, xa, ya)
    # command += "ASSERT({0}[0:0]=BVXOR({1}[0:0],{2}[0:0]));\n".format(w, pa, ca)
    # command += "ASSERT({0}[1:1]=BVXOR({1}[1:1],{2}[1:1]));\n".format(w, pa, ca)
    # command += "ASSERT({0}[2:2]=BVXOR({1}[2:2],{2}[2:2]));\n".format(w, pa, ca)
    #
    # # command += "ASSERT(NOT({0}[0:2]=0bin000));\n".format(w)
    # command += "ASSERT({0}=0bin00000000000000000000000000000111);\n".format(w)

    stp_file.write(command)
    return
