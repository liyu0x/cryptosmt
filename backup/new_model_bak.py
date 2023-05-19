# from ciphers import katan32_bct
# from ciphers import katan32
# import random
# from cryptanalysis import search
# import time
# import copy
# import os
# import math
# 
# 
# def find_single_trail(r, offset, switch_start_round, switch_rounds):
#     start_time = time.time()
#     cipher_bct = katan32_bct.katan32()
#     cipher = katan32.katan32()
#     save_file = "result/{0}-{1}-{2}-NEW_MODEL.txt".format(cipher.name, r, offset)
#     result_file = open(save_file, "w")
#     params = {
#         "rounds": r,
#         "uppertrail": 5,
#         "uweight": 0,
#         "upperlimit": 16,
#         "lowertrail": 5,
#         "lweight": 0,
#         "lowerlimit": 16,
#         "mode": 0,
#         "wordsize": 32,
#         "blocksize": 64,
#         "sweight": 0,
#         "endweight": 1000,
#         "iterative": False,
#         "boolector": False,
#         "dot": None,
#         "latex": None,
#         "nummessages": 1,
#         "timelimit": -1,
#         "fixedVariables": {},
#         "boomerangVariables": {},
#         "sboxSize": 4,
#         "design": "gfn",
#         "sbox": [],
#         "perm": [],
#         "bct": [[0] * 16 for _ in range(16)],
#         "blockedCharacteristics": [],
#         "offset": offset,
#         "switchStartRound": switch_start_round,
#         "switchRounds": switch_rounds
#     }
# 
#     while params["sweight"] < 32:
#         rnd_string_tmp = "%030x" % random.randrange(16 ** 30)
#         stp_file = "tmp/{}{}.stp".format(cipher_bct.name, rnd_string_tmp)
#         cipher_bct.createSTP(stp_file, params)
#         if params["boolector"]:
#             result = search.solveBoolector(stp_file)
#         else:
#             result = search.solveSTP(stp_file)
#         if not search.foundSolution(result):
#             print(
#                 "Rounds:{1}, No trails, weight:{0}".format(
#                     params["sweight"], params["rounds"]
#                 )
#             )
#             params["sweight"] += 1
#             continue
#         characteristic = ""
#         if params["boolector"]:
#             characteristic = search.parsesolveroutput.getCharBoolectorOutput(
#                 result, cipher_bct, params["rounds"]
#             )
#         else:
#             characteristic = search.parsesolveroutput.getCharSTPOutput(
#                 result, cipher_bct, params["rounds"]
#             )
# 
#         save_str = "\nrounds:{0}, switch-start-round:{1}, switch-rounds:{2}\n".format(r, switch_start_round,
#                                                                                       switch_rounds)
# 
#         # compute Prob for E_0
#         new_parameters = copy.deepcopy(params)
#         x_input_diff, x_out_diff = get_different(characteristic, 0, switch_start_round)
#         new_parameters["fixedVariables"].clear()
#         new_parameters["rounds"] = switch_start_round
#         new_parameters["blockedCharacteristics"].clear()
#         # new_parameters["fixedVariables"]["X0"] = x_input_diff
#         new_parameters["fixedVariables"]["X{}".format(switch_start_round)] = x_out_diff
#         new_parameters["sweight"] = 0  # need to optimize
#         new_parameters["offset"] = 0
#         prob_e0 = check_solutions(new_parameters, cipher)
#         save_str += "E0-INPUT:{0}, E0-OUTPUT:{1}, E0-PROB:{2}\n".format(x_input_diff, x_out_diff, prob_e0)
#         characteristic.printText()
#         # compute Prob for E_1
#         new_parameters = copy.deepcopy(params)
#         x_input_diff, x_out_diff = get_different(characteristic, 1, switch_start_round)
#         new_parameters["fixedVariables"].clear()
#         new_parameters["offset"] = switch_start_round + switch_rounds
#         new_parameters["rounds"] = r - switch_start_round - switch_rounds
#         new_parameters["blockedCharacteristics"].clear()
#         new_parameters["fixedVariables"]["X0"] = x_input_diff
#         new_parameters["fixedVariables"]["X{}".format(new_parameters["rounds"])] = x_out_diff
#         new_parameters["sweight"] = 0  # need to optimize
#         prob_e1 = check_solutions(new_parameters, cipher)
#         save_str += "E1-INPUT:{0}, E1-OUTPUT:{1}, E1-PROB:{2}\n".format(x_input_diff, x_out_diff, prob_e1)
#         final_prob = prob_e0 * prob_e0 * prob_e1 * prob_e1
#         save_str += "Finally Probability:{0}, Weight:{1}".format(str(final_prob), str(-math.log2(final_prob)))
#         result_file.write(save_str)
#         result_file.flush()
# 
# 
# def get_different(characteristic, start_round, end_round, index=0):
#     data = characteristic.getData()
# 
#     return data[start_round][index], data[end_round][index]
# 
# 
# def check_solutions(new_parameter, cipher, max_weight=32):
#     sat_logfile = "tmp/satlog{}.tmp".format(1234)
#     # Search until optimal weight + wordsize/8
#     prob = 0
#     while new_parameter["sweight"] < max_weight:
#         if os.path.isfile(sat_logfile):
#             os.remove(sat_logfile)
#         stp_file = "tmp/{}{}-{}.stp".format(cipher.name, "test", "12342")
#         cipher.createSTP(stp_file, new_parameter)
# 
#         # Start solver
#         sat_process = search.startSATsolver(stp_file)
#         log_file = open(sat_logfile, "w")
# 
#         # Find the number of solutions with the SAT solver
#         print("Finding all trails of weight {}".format(new_parameter["sweight"]))
# 
#         # Watch the process and count solutions
#         solutions = 0
#         while sat_process.poll() is None:
#             line = sat_process.stdout.readline().decode("utf-8")
#             log_file.write(line)
#             if "s SATISFIABLE" in line:
#                 solutions += 1
#             if solutions % 100 == 0:
#                 print("\tSolutions: {}\r".format(solutions // 2), end="")
# 
#         log_file.close()
#         if solutions > 0:
#             print("\tSolutions: {}".format(solutions // 2))
# 
#             assert solutions == search.countSolutionsLogfile(sat_logfile)
# 
#             # The encoded CNF contains every solution twice
#             solutions //= 2
#             prob += math.pow(2, -new_parameter["sweight"]) * solutions
#         new_parameter["sweight"] += 1
#     return prob
# 
# 
# for i in range(40, 60):
#     find_single_trail(i, 0, int(i / 2), 4)
