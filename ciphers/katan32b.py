# '''
# Created on May 10, 2022
# Modified on May 9, 2023
# 
# @author: jesenteh
# @modify: liyu
# '''
# 
# from parser import stpcommands
# from ciphers.cipher import AbstractCipher
# 
# 
# class katan32(AbstractCipher):
#     """
#     Represents the differential behaviour of Katan32 and can be used
#     to find differential characteristics for the given parameters.
#     It uses an alternative representation of Katan32 in ARX form.
#     """
# 
#     name = "katan32"
# 
#     IR = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0,
#           1, 1, 0, 1, 0, 1, 0, 1, 0, 1,
#           1, 1, 1, 0, 1, 1, 0, 0, 1, 1,
#           0, 0, 1, 0, 1, 0, 0, 1, 0, 0,
#           0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
#           1, 1, 1, 1, 0, 0, 0, 0, 1, 0,
#           0, 0, 0, 1, 0, 1, 0, 0, 0, 0,
#           0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
#           1, 1, 1, 1, 0, 1, 0, 1, 0, 0,
#           0, 1, 0, 1, 0, 1, 0, 0, 1, 1,
#           0, 0, 0, 0, 1, 1, 0, 0, 1, 1,
#           1, 0, 1, 1, 1, 1, 1, 0, 1, 1,
#           1, 0, 1, 0, 0, 1, 0, 1, 0, 1,
#           1, 0, 1, 0, 0, 1, 1, 1, 0, 0,
#           1, 1, 0, 1, 1, 0, 0, 0, 1, 0,
#           1, 1, 1, 0, 1, 1, 0, 1, 1, 1,
#           1, 0, 0, 1, 0, 1, 1, 0, 1, 1,
#           0, 1, 0, 1, 1, 1, 0, 0, 1, 0,
#           0, 1, 0, 0, 1, 1, 0, 1, 0, 0,
#           0, 1, 1, 1, 0, 0, 0, 1, 0, 0,
#           1, 1, 1, 1, 0, 1, 0, 0, 0, 0,
#           1, 1, 1, 0, 1, 0, 1, 1, 0, 0,
#           0, 0, 0, 1, 0, 1, 1, 0, 0, 1,
#           0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
#           1, 1, 0, 0, 0, 0, 0, 0, 0, 1,
#           0, 0, 1, 0]
# 
#     def ax_box(self, x):
#         x0 = x >> 3 & 0x1
#         x1 = x >> 2 & 0x1
#         x2 = x >> 1 & 0x1
#         x3 = x & 0x1
#         return (x0 & x1) ^ (x2 & x3)
# 
#     def ax_box_2(self, x):
#         x0 = x >> 1 & 0x1
#         x1 = x & 0x1
#         return x0 & x1
# 
#     def small_vari(self, x_in, x_out):
#         variables = ["{0}[{1}:{1}]".format(x_in, 19 + 5),
#                      "{0}[{1}:{1}]".format(x_in, 19 + 8),
#                      "{0}[{1}:{1}]".format(x_out, 19 + 5 + 1),
#                      "{0}[{1}:{1}]".format(x_out, 19 + 8 + 1)]
#         return variables
# 
#     def big_vari(self, x_in, x_out):
#         variables = ["{0}[{1}:{1}]".format(x_in, 3),
#                      "{0}[{1}:{1}]".format(x_in, 8),
#                      "{0}[{1}:{1}]".format(x_in, 10),
#                      "{0}[{1}:{1}]".format(x_in, 12),
#                      "{0}[{1}:{1}]".format(x_out, 3 + 1),
#                      "{0}[{1}:{1}]".format(x_out, 8 + 1),
#                      "{0}[{1}:{1}]".format(x_out, 10 + 1),
#                      "{0}[{1}:{1}]".format(x_out, 12 + 1)]
# 
#         return variables
# 
#     def getSbox(self):
#         return None
# 
#     def getSboxSize(self):
#         return 4
# 
#     def getDesign(self):
#         return "ax"
# 
#     def getPerm(self):
#         return None
# 
#     def getFormatString(self):
#         """
#         Returns the print format.
#         """
#         return ['X', 'Y', 'A', 'F', 'w']
# 
#     def createSTP(self, stp_filename, parameters):
#         """
#         Creates an STP file to find a characteristic for KATAN32 with
#         the given parameters.
#         """
#         wordsize = parameters["wordsize"]
#         rounds = parameters["rounds"]
#         weight = parameters["sweight"]
#         offset = parameters["offset"]
# 
#         with open(stp_filename, 'w') as stp_file:
#             header = ("% Input File for STP\n% KATAN32 w={}"
#                       "rounds={} with IR offset={}\n\n\n".format(wordsize, rounds, offset))
#             stp_file.write(header)
# 
#             # Setup variables
#             # x = input (32), f = outputs of AND operation (Only 3 bits required, use 3 bits to store)
#             # a = active or inactive AND operation (Only 3 bits required, use 3 bits to store)
#             x = ["X{}".format(i) for i in range(rounds + 1)]
#             y = ["Y{}".format(i) for i in range(rounds + 1)]
#             f = ["F{}".format(i) for i in range(rounds)]
#             a = ["A{}".format(i) for i in range(rounds)]
#             yf = ["YF{}".format(i) for i in range(rounds)]
#             ya = ["YA{}".format(i) for i in range(rounds)]
# 
#             # w = weight
#             w = ["w{}".format(i) for i in range(rounds)]
# 
#             stpcommands.setupVariables(stp_file, x, wordsize)
#             stpcommands.setupVariables(stp_file, f, wordsize)
#             stpcommands.setupVariables(stp_file, a, wordsize)
#             stpcommands.setupVariables(stp_file, w, wordsize)
#             stpcommands.setupVariables(stp_file, y, wordsize)
#             stpcommands.setupVariables(stp_file, ya, wordsize)
#             stpcommands.setupVariables(stp_file, yf, wordsize)
# 
#             stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)
# 
#             # Modify start_round to start from different positions
# 
#             # E0 or E1
#             
#                 for i in range(rounds):
#                     self.setupKatanRound(stp_file, x[i], f[i], a[i], x[i + 1],
#                                          w[i], wordsize, i, offset)
#                 stpcommands.assertNonZero(stp_file, x, wordsize)
#             else:
#                 # Em
#                 command = ""
#                 for i in range(rounds):
#                     self.setupKatanRound(stp_file, x[i], f[i], a[i], x[i + 1],
#                                          w[i], wordsize, i, offset, True)
#                 for i in range(1, rounds):
#                     self.setupKatanRound(stp_file, y[i], yf[i], ya[i], y[i + 1],
#                                          w[i], wordsize, i, offset, True)
# 
#                 for i in range(rounds):
#                     command += stpcommands.and_bct(self.small_vari(x[i], y[i + 1]), self.ax_box_2, 2)
#                     command += stpcommands.and_bct(self.big_vari(x[i], y[i + 1]), self.ax_box, 4)
# 
#                 stpcommands.assertNonZero(stp_file, x, wordsize)
#                 stpcommands.assertNonZero(stp_file, y, wordsize)
#                 stp_file.write(command)
# 
#             extra = parameters["extra_command"]
#             stp_file.write(extra)
# 
#             # Iterative characteristics only
#             # Input difference = Output difference
#             if parameters["iterative"]:
#                 stpcommands.assertVariableValue(stp_file, x[0], x[rounds])
# 
#             for key, value in parameters["fixedVariables"].items():
#                 stpcommands.assertVariableValue(stp_file, key, value)
# 
#             for char in parameters["blockedCharacteristics"]:
#                 stpcommands.blockCharacteristic(stp_file, char, wordsize)
# 
#             stpcommands.setupQuery(stp_file)
# 
#         return
# 
#     def verify_switch(self, stp_filename, parameters):
#         wordsize = parameters["wordsize"]
#         rounds = parameters["rounds"]
#         weight = parameters["sweight"]
#         offset = parameters["offset"]
# 
#         with open(stp_filename, 'w') as stp_file:
#             header = ("% Input File for STP\n% KATAN32 w={}"
#                       "rounds={} with IR offset={}\n\n\n".format(wordsize, rounds, offset))
#             stp_file.write(header)
# 
#             # Setup variables
#             # x = input (32), f = outputs of AND operation (Only 3 bits required, use 3 bits to store)
#             # a = active or inactive AND operation (Only 3 bits required, use 3 bits to store)
#             x = ["X{}".format(i) for i in range(rounds + 1)]
#             y = ["Y{}".format(i) for i in range(rounds + 1)]
#             f = ["F{}".format(i) for i in range(rounds)]
#             a = ["A{}".format(i) for i in range(rounds)]
#             yf = ["YF{}".format(i) for i in range(rounds)]
#             ya = ["YA{}".format(i) for i in range(rounds)]
# 
#             # w = weight
#             w = ["w{}".format(i) for i in range(rounds)]
# 
#             stpcommands.setupVariables(stp_file, x, wordsize)
#             stpcommands.setupVariables(stp_file, f, wordsize)
#             stpcommands.setupVariables(stp_file, a, wordsize)
#             stpcommands.setupVariables(stp_file, w, wordsize)
#             stpcommands.setupVariables(stp_file, y, wordsize)
#             stpcommands.setupVariables(stp_file, ya, wordsize)
#             stpcommands.setupVariables(stp_file, yf, wordsize)
# 
#             stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)
# 
#             # Modify start_round to start from different positions
# 
#             # E0 or E1
#             if not switch:
#                 for i in range(rounds):
#                     self.setupKatanRound(stp_file, x[i], f[i], a[i], x[i + 1],
#                                          w[i], wordsize, i, offset)
#                 stpcommands.assertNonZero(stp_file, x, wordsize)
#             else:
#                 # Em
#                 command = ""
#                 for i in range(rounds):
#                     self.setupKatanRound(stp_file, x[i], f[i], a[i], x[i + 1],
#                                          w[i], wordsize, i, offset, True)
#                 for i in range(1, rounds):
#                     self.setupKatanRound(stp_file, y[i], yf[i], ya[i], y[i + 1],
#                                          w[i], wordsize, i, offset, True)
# 
#                 for i in range(rounds):
#                     command += stpcommands.and_bct(self.small_vari(x[i], y[i + 1]), self.ax_box_2, 2)
#                     command += stpcommands.and_bct(self.big_vari(x[i], y[i + 1]), self.ax_box, 4)
# 
#                 stpcommands.assertNonZero(stp_file, x, wordsize)
#                 stpcommands.assertNonZero(stp_file, y, wordsize)
#                 stp_file.write(command)
# 
#             extra = parameters["extra_command"]
#             stp_file.write(extra)
# 
#             # Iterative characteristics only
#             # Input difference = Output difference
#             if parameters["iterative"]:
#                 stpcommands.assertVariableValue(stp_file, x[0], x[rounds])
# 
#             for key, value in parameters["fixedVariables"].items():
#                 stpcommands.assertVariableValue(stp_file, key, value)
# 
#             for char in parameters["blockedCharacteristics"]:
#                 stpcommands.blockCharacteristic(stp_file, char, wordsize)
# 
#             stpcommands.setupQuery(stp_file)
# 
#         return
# 
#     def setupKatanRound(self, stp_file, x_in, f, a, x_out, w, wordsize, r, offset, switch=False):
#         """
#         Model for differential behaviour of one round KATAN32
#         """
#         command = ""
# 
#         # Check if AND is active
#         # a[0] = x[3] | x[8]
#         command += "ASSERT({0}[0:0] = {1}[3:3]|{2}[8:8]);\n".format(a, x_in, x_in)
#         # a[1] = x[10]| x[12]
#         command += "ASSERT({0}[1:1] = {1}[10:10]|{2}[12:12]);\n".format(a, x_in, x_in)
#         # Locations for L1 = 5 and 8. In full 32-bit register, 5+19 = 24, 8+19 = 27
#         # a[2] = x[24] | x[27]
#         command += "ASSERT({0}[2:2] = {1}[24:24]|{2}[27:27]);\n".format(a, x_in, x_in)
# 
#         # Calculate weights and output of AND operations
#         # If a=1, w = 1, otherwise, w = 0
#         # If a = 1, f = 0/1, otherwise, f = 0
#         # for i in range (3):
#         #     command += "ASSERT({0}[{2}:{2}] = {1}[{2}:{2}]);\n".format(w,a,i)
#         #     command += "ASSERT(BVLE({0}[{2}:{2}],{1}[{2}:{2}]));\n".format(f,a,i)
# 
#         if not switch:
#             # w[1]=a[2]
#             command += "ASSERT({0}[1:1] = {1}[2:2]);\n".format(w, a)  # AND in the L1 register
#             # As long as either 1 AND operation in L2 register is active, prob is 1
#             # w[0]=a[0]|a[1]
#             command += "ASSERT({0}[0:0] = {1}[0:0] | {1}[1:1]);\n".format(w, a)
# 
#         for i in range(3):
#             command += "ASSERT(BVLE({0}[{2}:{2}],{1}[{2}:{2}]));\n".format(f, a, i)
# 
#         # Permutation layer (shift left L2 by 1 except for position 18)
#         for i in range(0, 18):
#             command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(x_out, i + 1, x_in, i)
#         # Permutation layer (shift left L1 by 1 except for position 31 (L1_12))
#         for i in range(19, 31):
#             command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(x_out, i + 1, x_in, i)
# 
#         # Perform XOR operation for to get bits for position L2_0 and 19 (L1_0)
#         # x_out[0] = x[31]^x[26]^a[2]^(x[22]&IR[r])
#         command += "ASSERT({0}[0:0] = BVXOR({1}[31:31],BVXOR({1}[26:26],BVXOR({2}[2:2],({1}[22:22]&0b{3})))));\n".format(
#             x_out, x_in, f, self.IR[r + offset])
#         # x_out[19] = x[18]^a[1]^x[7]^a[0]
#         command += "ASSERT({0}[19:19] = BVXOR({1}[18:18],BVXOR({2}[1:1],BVXOR({1}[7:7],{2}[0:0]))));\n".format(x_out,
#                                                                                                                x_in, f)
# 
#         command += "ASSERT(0b000000000000000000000000000000 = {0}[31:2]);\n".format(
#             w)  # Use 2 bits to store would be sufficient
#         command += "ASSERT(0b00000000000000000000000000000 = {0}[31:3]);\n".format(f)
#         command += "ASSERT(0b00000000000000000000000000000 = {0}[31:3]);\n".format(a)
# 
#         stp_file.write(command)
#         return
