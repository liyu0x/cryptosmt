# """
# Created on May 9, 2023
#
# @author: li yu
# """
# import time
# import os
# import math
# from cryptanalysis import search
# from parser import parsesolveroutput, stpcommands
#
#
# def compute_rx_boomerang_differential(cipher, parameters):
#     start_time = time.time()
#     parameters["cipher_obj"] = cipher
#     print("----")
#     print("Running initial boomerang search")
#     print("----")
#
#     upper_block = ""
#     while not search.reachedTimelimit(start_time, parameters["timelimit"]) and \
#             parameters["previous_upper_weight"] < parameters["endweight"]:
#         upper_trail = search_differential(parameters, start_time, extra_command=upper_block)
#         if upper_trail == "":
#             continue
#         parameters["upper_trail"] = upper_trail
#         middle_block = ""
#         while not search.reachedTimelimit(start_time, parameters["timelimit"]):
#             middle_trail = search_differential(parameters, start_time, "middle", middle_block)
#             if middle_trail == "":
#                 break
#             parameters["middle_trail"] = middle_trail
#             middle_block += "ASSERT(NOT(Y{0}={1}));\n".format(parameters["middletrail"], middle_trail.getOutputDiff(1))
#             lower_trail = search_differential(parameters, start_time, "lower")
#             if lower_trail == "":
#                 continue
#             alpha, beta, gamma, delta = get_alpha_beta_gamma_delta(upper_trail, lower_trail, parameters)
#             compute_entire_trail_cluster_prob(parameters, alpha, beta, gamma, delta, start_time)
#
#
# def get_alpha_beta_gamma_delta(upper_trail, lower_trail, parameters):
#     alpha = upper_trail.getInputDiff()
#     beta = upper_trail.getOutputDiff()
#     gamma = lower_trail.getInputDiff()
#     delta = lower_trail.getOutputDiff()
#     return alpha, beta, gamma, delta
#
#
# def search_differential(parameters, start_time, boomerang_face="upper", extra_command=""):
#     parameters["boomerang_face"] = boomerang_face
#     cipher = parameters["cipher_obj"]
#     characteristic = None
#     trail = ""
#     block = ""
#     store_weight = ""
#     if boomerang_face == "upper":
#         trail = "uppertrail"
#         parameters["sweight"] = parameters["uweight"]
#         block = "blockedUpperCharacteristics"
#         store_weight = "previous_upper_weight"
#     elif boomerang_face == "middle":
#         trail = "middletrail"
#         parameters["sweight"] = parameters["mweight"]
#         upper_trail = parameters["upper_trail"]
#         parameters["fixedVariables"].clear()
#         parameters["fixedVariables"]["X0"] = upper_trail.getOutputDiff()
#         block = "blockedMiddleCharacteristics"
#         store_weight = "previous_middle_weight"
#     elif boomerang_face == "lower":
#         trail = "lowertrail"
#         middle_trail = parameters["middle_trail"]
#         parameters["sweight"] = parameters["lweight"]
#         parameters["fixedVariables"].clear()
#         parameters["fixedVariables"]["X0"] = middle_trail.getOutputDiff(1)
#         block = "blockedLowerCharacteristics"
#         store_weight = "previous_lower_weight"
#
#     parameters["blockedCharacteristics"].clear()
#     parameters["blockedCharacteristics"] = parameters[block].copy()
#     while not search.reachedTimelimit(start_time, parameters["timelimit"]) and \
#             parameters["sweight"] < parameters["endweight"]:
#         print("Weight: {} Time: {}s".format(parameters["sweight"],
#                                             round(time.time() - start_time, 2)))
#         # Construct problem instance for given parameters
#         stp_file = "tmp/{}-{}{}-{}-{}.stp".format(boomerang_face, cipher.name,
#                                                   parameters["wordsize"], parameters[trail], start_time)
#
#         # Fix number of rounds
#         parameters["rounds"] = parameters[trail]
#
#         parameters["extra_command"] = extra_command
#         cipher.createSTP(stp_file, parameters)
#         parameters["extra_command"] = ""
#
#         if parameters["boolector"]:
#             result = search.solveBoolector(stp_file)
#         else:
#             result = search.solveSTP(stp_file)
#             characteristic = ""
#
#         # Check if a characteristic was found
#         if search.foundSolution(result):
#             current_time = round(time.time() - start_time, 2)
#             print("---")
#             print(("{} Trail for {} - Rounds {} - Wordsize {} - "
#                    "Weight {} - Time {}s".format(boomerang_face,
#                                                  cipher.name,
#                                                  parameters[trail],
#                                                  parameters["wordsize"],
#                                                  parameters["sweight"],
#                                                  current_time)))
#             if parameters["boolector"]:
#                 characteristic = parsesolveroutput.getCharBoolectorOutput(
#                     result, cipher, parameters[trail])
#             else:
#                 characteristic = parsesolveroutput.getCharSTPOutput(
#                     result, cipher, parameters[trail])
#             characteristic.printText()
#             print("----")
#             break
#         parameters["sweight"] += 1
#         print("----")
#
#     if parameters["sweight"] >= parameters["endweight"] and boomerang_face == "upper":
#         print("Weight limit has been reached. Ending search.")
#         quit()
#     parameters[store_weight] = parameters["sweight"]
#     return characteristic
#
#
# def compute_entire_trail_cluster_prob(parameters, alpha, beta, gamma, delta, start_time):
#     boomerang_prob = 0
#     diff_upper = 0
#     diff_lower = 0
#     switch_prob = 1
#     upper_weight = parameters["previous_upper_weight"]
#     lower_weight = parameters["previous_lower_weight"]
#     cipher = parameters["cipher_obj"]
#
#     # Fix starting point if it has not been set in boomerang Variables
#     if "X0" not in parameters["boomerangVariables"]:
#         parameters["boomerangVariables"]["X0"] = alpha
#         print("Fixed X0 in boomerang to {}".format(parameters["boomerangVariables"]["X0"]))
#         print("----")
#     # Fix end point if it has not been set in boomerang Variables
#     if "X{}".format(parameters["lowertrail"]) not in parameters["boomerangVariables"]:
#         parameters["boomerangVariables"]["X{}".format(parameters["lowertrail"])] = delta
#         print("Fixed X{} in boomerang to {}".format(parameters["lowertrail"], parameters["boomerangVariables"][
#             "X{}".format(parameters["lowertrail"])]))
#         print("----")
#     # Perform clustering for upper if not done, then cluster lower
#     while not search.reachedTimelimit(start_time, parameters["timelimit"]) and diff_upper == 0:
#         diff_upper = cluster_search(cipher, parameters, alpha, beta, upper_weight, start_time, "upper")
#     diff_lower = 0
#     while not search.reachedTimelimit(start_time, parameters["timelimit"]) and diff_lower == 0:
#         diff_lower = cluster_search(cipher, parameters, gamma, delta, lower_weight, start_time, "lower")
#
#     if search.reachedTimelimit(start_time, parameters["timelimit"]):
#         return 99
#
#     boomerang_prob += diff_upper * diff_upper * diff_lower * diff_lower * switch_prob
#     print("Found boomerang trail: {}, {}, {}".format(math.log(diff_upper, 2), math.log(diff_lower, 2),
#                                                      math.log(switch_prob, 2)))
#     print("Boomerang probability: {}".format(math.log(boomerang_prob, 2)))
#     print("----")
#
#     # After searching for all possible optimal lower trails for the given upper trail, block upper trail
#     print("Completed trail search with boomerang probability of {}".format(math.log(boomerang_prob, 2)))
#     parameters["uweight"] = upper_weight
#     return boomerang_prob
#
#
# def cluster_search(cipher, parameters, delta_in, delta_out, weight, timestamp, boomerang_face="upper"):
#     """
#     Perform clustering for one face of a boomerang differential
#     """
#     # Set parameters for targeted boomerang face. Maintained for consistency.
#     trail = ""
#     limit = ""
#     parameters["boomerang_face"] = boomerang_face
#     if boomerang_face == "upper":
#         trail = "uppertrail"
#         limit = "upperlimit"
#     else:
#         trail = "lowertrail"
#         limit = "lowerlimit"
#
#     start_time = timestamp
#
#     print("Cluster {} differential".format(boomerang_face))
#
#     # Clear blocked characteristics
#     parameters["blockedCharacteristics"].clear()
#
#     # Setup search
#     # rnd_string_tmp = '%030x' % random.randrange(16**30)
#     diff_prob = 0
#     characteristics_found = 0
#     sat_logfile = "tmp/satlog{}.tmp".format(timestamp)
#
#     parameters["fixedVariables"].clear()
#     parameters["fixedVariables"]["X0"] = delta_in
#     parameters["fixedVariables"]["X{}".format(parameters[trail])] = delta_out
#     parameters["sweight"] = weight
#
#     # TODO: Remove later
#     print("XO - ", delta_in)
#     print("X{} -".format(parameters[trail]), delta_out)
#
#     # Fix number of rounds
#     parameters["rounds"] = parameters[trail]
#
#     # Search until optimal weight + wordsize/8
#     while not search.reachedTimelimit(start_time, parameters["timelimit"]) and \
#             parameters["sweight"] < weight + parameters["wordsize"] / parameters[limit]:
#
#         if os.path.isfile(sat_logfile):
#             os.remove(sat_logfile)
#
#         stp_file = "tmp/{}{}-{}.stp".format(cipher.name, trail, timestamp)
#         cipher.createSTP(stp_file, parameters)
#
#         # Start solver
#         sat_process = search.startSATsolver(stp_file)
#         log_file = open(sat_logfile, "w")
#
#         # Find the number of solutions with the SAT solver
#         print("Finding all trails of weight {}".format(parameters["sweight"]))
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
#         print("\tSolutions: {}".format(solutions // 2))
#
#         assert solutions == search.countSolutionsLogfile(sat_logfile)
#
#         # The encoded CNF contains every solution twice
#         solutions //= 2
#
#         # Print result
#         diff_prob += math.pow(2, -parameters["sweight"]) * solutions
#         characteristics_found += solutions
#         if diff_prob > 0.0:
#             # print("\tSolutions: {}".format(solutions))
#             print("\tTrails found: {}".format(characteristics_found))
#             print("\tCurrent Probability: " + str(math.log(diff_prob, 2)))
#             print("\tTime: {}s".format(round(time.time() - start_time, 2)))
#         parameters["sweight"] += 1
#
#     print("----")
#     return diff_prob
