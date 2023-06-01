from ciphers import simon
import multiprocessing
from simon_bct_search_task2 import check_solutions
import random
from cryptanalysis import search
import copy
import math


MAX_THREAD = 12

MAX_SINGLE_TRAIL_SERACH_LIMIT = 4
MAX_CLUSTER_TRAIL_SERACH_LIMIT = 10
SWITCH_ROUNDS = 1
WORDSIZE = 16

POOL = multiprocessing.Pool(processes=MAX_THREAD)

def find_single_trail(cipher, r, offset, switch_start_round, switch_rounds, sweight=0):
    max_weight = 1000000
    max_weight_setting = False
    save_file = "result/{0}-{1}-{2}-NEW_MODEL.txt".format(cipher.name, r, offset)
    result_file = open(save_file, "w")
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
        "switchRounds": switch_rounds
    }
    rnd_string_tmp = "%030x" % random.randrange(16 ** 30)
    stp_file = "tmp/{0}-{1}-{2}.stp".format(cipher.name, rnd_string_tmp, r)
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
            continue
        characteristic = search.parsesolveroutput.getCharSTPOutput(result, cipher, params["rounds"])
        
        if not max_weight_setting:
            max_weight = params["sweight"] + MAX_SINGLE_TRAIL_SERACH_LIMIT
            max_weight_setting = True
        characteristic.printText()
        # Cluster Search
        new_parameters = copy.deepcopy(params)
        trails_data = characteristic.getData()
        input_diff_l = trails_data[0][0]
        input_diff_r = trails_data[0][1]
        output_diff_l = trails_data[r][2]
        output_diff_r = trails_data[r][3]
        new_parameters["fixedVariables"].clear()
        new_parameters["blockedCharacteristics"].clear()
        new_parameters["fixedVariables"]["XL0"] = input_diff_l
        new_parameters["fixedVariables"]["XR0"] = input_diff_r
        new_parameters["fixedVariables"]["YL{}".format(r)] = output_diff_l
        new_parameters["fixedVariables"]["YR{}".format(r)] = output_diff_r
        muilt_core = []
        p = 0
        for w in (0,MAX_CLUSTER_TRAIL_SERACH_LIMIT):
            muilt_core.append(
                POOL.apply_async(check_solutions, args=(new_parameters, cipher, new_parameters["sweight"] + w))
                )
        for task in muilt_core:
            p += task.get()
        p *= p
        rectangle_weight = math.log2(p)
        save_str = "cipher:{0}, rounds:{1}, inputDiff:{2}, outputDiff:{3}, boomerang weight:{4}, rectangle weight:{5}, switchStartRound:{6}, SwitchRounds:{7}\n".format(
            cipher.name, r, input_diff_l+input_diff_r, output_diff_l+output_diff_r, -params["sweight"] * 2, -rectangle_weight, switch_start_round,
            switch_rounds)
        result_file.write(save_str)
        result_file.flush()
        params["sweight"] += 1


if __name__ == '__main__':
    c = simon.SimonCipher()
    c.name = "simon32"
    start_rounds = 14
    find_single_trail(c, start_rounds, start_rounds, 0, 7, 30)


