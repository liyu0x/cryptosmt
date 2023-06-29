import random
import copy
import os
import math
import uuid
import util
from cryptanalysis import search
from ciphers import katan32bct

MAX_SINGLE_TRAIL_SERACH_LIMIT = 4
MAX_CLUSTER_TRAIL_SERACH_LIMIT = 99
START_ROUND = 83
END_ROUND = 88
SWITCH_ROUNDS = 4
WORDSIZE = 32
START_WEIGHT = 0
THRESHOLD = 6

RESULT_DIC = "katan32_result/"
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
        "bbbb": []
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
        new_parameters["bbbb"].clear()

        # input diff
        input_diff = trails_data[0][0]

        # output diff
        output_diff = trails_data[r][1]

        # switch diff
        switch_input_diff = trails_data[switch_start_round][0]
        switch_output_diff = trails_data[switch_start_round + switch_rounds][1]

        # upper trail
        upper_weight = 0
        for i in range(0, switch_start_round + switch_rounds):
            upper_weight += int(trails_data[i][2])

        # lower weight
        lower_weight = 0
        for i in range(switch_start_round + switch_rounds, r):
            lower_weight += int(trails_data[i][2])

        new_parameters["fixedVariables"]["X0"] = input_diff
        new_parameters["fixedVariables"]["Y{}".format(r)] = output_diff

        prob = check_solutions(new_parameters, cipher, MAX_CLUSTER_TRAIL_SERACH_LIMIT)

        if prob > 0:
            rectangle_weight = math.log2(prob)
        else:
            rectangle_weight = 99999

        save_str = "inputDiff:{0}, outputDiff:{1}, boomerang weight:{2}, rectangle weight:{3}\n".format(input_diff,
                                                                                                        output_diff,
                                                                                                        -params[
                                                                                                            'sweight'] * 2,
                                                                                                        rectangle_weight)

        save_str += "\t upperInDiff:{0}, upperOutDiff:{1}, weight:{2}\n".format(input_diff, switch_input_diff,
                                                                                upper_weight)
        save_str += "\t lowerInDiff:{0}, lowerOutDiff:{1}, weight:{2}\n".format(switch_output_diff, output_diff,
                                                                                lower_weight)
        result_file.write(save_str)
        result_file.flush()

        save_str = "{0},{1},{2},{3},{4},{5},{6}\n".format(input_diff, switch_input_diff, switch_output_diff,
                                                          output_diff,
                                                          params["rounds"],
                                                          -params['sweight'], rectangle_weight)
        result_list_file.write(save_str)
        result_list_file.flush()
        # params["sweight"] += 1
        params["bbbb"].append(characteristic)


def check_solutions(new_parameter, cipher, end_weight):
    end_weight += new_parameter['sweight']
    prob = 0
    start_time = str(uuid.uuid4())
    stp_file = TEMP_DIC + "{}{}-{}.stp".format(cipher.name, "clutesr", start_time)
    sat_logfile = TEMP_DIC + "satlog-{}-{}.tmp".format(cipher.name, start_time)
    last_weight = 0
    count = 0
    while new_parameter['sweight'] <= end_weight:
        if count > THRESHOLD:
            break
        new_weight = last_weight
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
        log_file.close()
        if solutions > 0:
            print("\tSolutions: {}".format(solutions / 2))
            assert solutions == search.countSolutionsLogfile(sat_logfile)
            prob += math.pow(2, -new_parameter["sweight"] * 2) * (solutions / 2)
            new_weight = int(math.log2(prob))
        new_parameter['sweight'] += 1
        print("Cluster Searching Stage|Current Weight:{0}".format(new_weight))
        if new_weight == last_weight:
            count += 1
        else:
            last_weight = new_weight
    return prob


if __name__ == '__main__':
    start_round = START_ROUND
    end_round = start_round + 1 if END_ROUND == -1 else END_ROUND
    for r in range(start_round, end_round):
        util.makedirs([RESULT_DIC, TEMP_DIC])
        c = katan32bct.katan32()
        c.name = "katan32"
        start_rounds = r
        switch_start_round = int(start_rounds / 2) - int(SWITCH_ROUNDS / 2)
        find_single_trail(c, start_rounds, 0, switch_start_round, SWITCH_ROUNDS, START_WEIGHT)
