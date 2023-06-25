import random
import copy
import os
import math
import uuid
import util
from cryptanalysis import search
from ciphers import simonbct

MAX_SINGLE_TRAIL_SERACH_LIMIT = 0
MAX_CLUSTER_TRAIL_SERACH_LIMIT = -1
TOTAL_ROUNDS = 13
SWITCH_ROUNDS = 1
WORDSIZE = 16
START_WEIGHT = 0

RESULT_DIC = "simon_result/"
TEMP_DIC = "tmp/"


def find_single_trail(cipher, r, offset, switch_start_round, switch_rounds, sweight=0):
    max_weight = 999
    max_weight_setting = False
    save_file = RESULT_DIC + "{0}-{1}.txt".format(cipher.name, r)
    save_list_file = RESULT_DIC + "{0}-{1}-LIST.txt".format(cipher.name, r)
    result_file = open(save_file, "w")
    result_list_file = open(save_list_file, 'w')
    params = {
        "rounds": r,
        "uppertrail": 5,
        "uweight": 0,
        "upperlimit": 16,
        "lowertrail": 5,
        "lweight": 0,
        "lowerlimit": 16,
        "mode": 0,
        "wordsize": WORDSIZE,
        "blocksize": 64,
        "sweight": sweight,
        "endweight": 1000,
        "iterative": False,
        "boolector": False,
        "dot": None,
        "latex": None,
        "nummessages": 1,
        "timelimit": -1,
        "fixedVariables": {},
        "boomerangVariables": {},
        "sboxSize": 4,
        "design": "gfn",
        "sbox": [],
        "perm": [],
        "bct": [[0] * 16 for _ in range(16)],
        "blockedCharacteristics": [],
        "offset": offset,
        "switchStartRound": switch_start_round,
        "switchRounds": switch_rounds,
        "bbbb": [],
        "cccc": []
    }
    rnd_string_tmp = "%030x" % random.randrange(16 ** 30)
    stp_file = TEMP_DIC + "{0}-{1}-{2}.stp".format(cipher.name, rnd_string_tmp, r)
    while params["sweight"] <= max_weight:
        cipher.createSTP(stp_file, params)
        if params["boolector"]:
            result = search.solveBoolector(stp_file)
        else:
            result = search.solveSTP(stp_file)
        if not search.foundSolution(result):
            print(
                "Rounds:{1}, No trails, weight:{0}\n".format(
                    params["sweight"], params["rounds"]
                )
            )
            params["sweight"] += 1
            params["fixedVariables"].clear()
            continue

        characteristic = search.parsesolveroutput.getCharSTPOutput(result, cipher, params["rounds"])

        if not max_weight_setting:
            max_weight = params["sweight"] + MAX_SINGLE_TRAIL_SERACH_LIMIT
            max_weight_setting = True
        characteristic.printText()
        # Cluster Search
        trails_data = characteristic.getData()
        new_parameters = copy.deepcopy(params)

        new_parameters["blockedCharacteristics"].clear()
        new_parameters["fixedVariables"].clear()

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

        # upper trail
        upper_weight = 0
        for i in range(0, switch_start_round + switch_rounds):
            upper_weight += int(trails_data[i][4])

        # lower weight
        lower_weight = 0
        for i in range(switch_start_round + switch_rounds, r):
            lower_weight += int(trails_data[i][4])

        new_parameters["fixedVariables"]["XL0"] = input_diff_l
        new_parameters["fixedVariables"]["XR0"] = input_diff_r

        new_parameters["fixedVariables"]["YL{}".format(r)] = output_diff_l
        new_parameters["fixedVariables"]["YR{}".format(r)] = output_diff_r

        prob, sols = check_solutions(new_parameters, cipher, MAX_CLUSTER_TRAIL_SERACH_LIMIT)
        sols = 0
        # prob = check_all_solutions(new_parameters, cipher)

        if prob > 0:
            rectangle_weight = math.log2(prob)
        else:
            rectangle_weight = 99999
        input_diff_r = input_diff_r.replace("0x", "")
        output_diff_r = output_diff_r.replace("0x", "")

        save_str = "inputDiff:{0}, outputDiff:{1}, boomerang weight:{2}, rectangle weight:{3}\n".format(input_diff,
                                                                                                        output_diff,
                                                                                                        -params[
                                                                                                            'sweight'] * 2,
                                                                                                        rectangle_weight)
        save_str += "\t upperInDiff:{0}, upperOutDiff:{1}, weight:{2}\n".format(input_diff, switch_input, upper_weight)
        save_str += "\t lowerInDiff:{0}, lowerOutDiff:{1}, weight:{2}\n".format(switch_output, output_diff,
                                                                                lower_weight)

        result_file.write(save_str)
        result_file.flush()

        save_str = "{0},{1},{2},{3},{4},{5},{6}\n".format(input_diff, switch_input, switch_output, output_diff,
                                                          params["rounds"],
                                                          -params['sweight'], rectangle_weight)
        result_list_file.write(save_str)
        result_list_file.flush()
        # params["sweight"] += 1
        params["bbbb"].append(characteristic)


def check_all_solutions(new_parameter, cipher):
    new_parameter['bbbb'].clear()
    prob = 0
    start_time = str(uuid.uuid4())
    stp_file = TEMP_DIC + "{}{}-{}.stp".format(cipher.name, "clutesr", start_time)
    m = 0
    current_weight = new_parameter['sweight']
    while True:
        if new_parameter['sweight'] != current_weight:
            prob += math.pow(2, -current_weight * 2) * m * m
            m = 0
            current_weight = new_parameter['sweight']
        cipher.createSTP(stp_file, new_parameter)
        result = search.solveSTP(stp_file)

        # check
        if not search.foundSolution(result):
            if new_parameter['sweight'] > 999:
                break
            new_parameter['sweight'] += 1
            continue
        characteristic = search.parsesolveroutput.getCharSTPOutput(result, cipher, new_parameter["rounds"])
        if characteristic.characteristic_data == {}:
            new_parameter['sweight'] += 1
            continue

        m += 1
        # prob += math.pow(2, -new_parameter['sweight'] * 2)
        new_parameter["cccc"].append(characteristic)
    return prob


def check_solutions(new_parameter, cipher, end_weight):
    new_parameter['bbbb'].clear()
    end_weight += new_parameter['sweight']
    prob = 0
    sol = 0
    start_time = str(uuid.uuid4())
    stp_file = TEMP_DIC + "{}{}-{}.stp".format(cipher.name, "clutesr", start_time)
    sat_logfile = TEMP_DIC + "satlog-{}-{}.tmp".format(cipher.name, start_time)
    while new_parameter['sweight'] <= end_weight:
        if os.path.isfile(sat_logfile):
            os.remove(sat_logfile)
        cipher.createSTP(stp_file, new_parameter)

        # Start solver
        sat_process = search.startSATsolver(stp_file)
        log_file = open(sat_logfile, "w")

        # Find the number of solutions with the SAT solver
        print("Finding all trails of weight {}".format(new_parameter["sweight"]))

        # Watch the process and count solutions
        solutions = 0
        while sat_process.poll() is None:
            line = sat_process.stdout.readline().decode("utf-8")
            log_file.write(line)
            if "s SATISFIABLE" in line:
                solutions += 1
            # if solutions % 100 == 0:
            # print("\t Rounds: {1}, Wedight: {2}, Solutions: {0}\r".format(solutions // 2, new_parameter['rounds'],new_parameter['sweight']), end="")

        log_file.close()
        if solutions > 0:
            print("\tSolutions: {}".format(solutions // 2))

            assert solutions == search.countSolutionsLogfile(sat_logfile)

            # The encoded CNF contains every solution twice
            solutions //= 2
            sol += solutions
            prob += math.pow(2, -new_parameter["sweight"] * 2) * (solutions ** 1)
        new_parameter['sweight'] += 1
    return prob, sol


if __name__ == '__main__':
    util.makedirs([RESULT_DIC, TEMP_DIC])
    c = simonbct.SimonCipher()
    c.name = "simon32"
    start_rounds = TOTAL_ROUNDS
    switch_start_round = int(start_rounds / 2) - int(SWITCH_ROUNDS / 2)
    find_single_trail(c, start_rounds, 0, switch_start_round, SWITCH_ROUNDS, START_WEIGHT)
