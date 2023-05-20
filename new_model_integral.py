from ciphers import katan32_bct
import random
from cryptanalysis import search
import time
import copy
import os
import math
import threading
import multiprocessing

MAX_THREAD = 6


def find_single_trail(cipher, r, offset, switch_start_round, switch_rounds):
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
        "wordsize": 32,
        "blocksize": 64,
        "sweight": 0,
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
    while params["sweight"] < 32:
        cipher.createSTP(stp_file, params)
        if params["boolector"]:
            result = search.solveBoolector(stp_file)
        else:
            result = search.solveSTP(stp_file)
        if not search.foundSolution(result):
            print(
                "Rounds:{1}, No trails, weight:{0}".format(
                    params["sweight"], params["rounds"]
                )
            )
            params["sweight"] += 1
            continue
        characteristic = search.parsesolveroutput.getCharSTPOutput(result, cipher, params["rounds"])

        # Cluster Search
        new_parameters = copy.deepcopy(params)
        trails_data = characteristic.getData()
        input_diff = trails_data[0][0]
        output_diff = trails_data[r][1]
        new_parameters["fixedVariables"].clear()
        new_parameters["blockedCharacteristics"].clear()
        new_parameters["fixedVariables"]["X0"] = input_diff
        new_parameters["fixedVariables"]["Y{}".format(r)] = output_diff
        characteristic.printText()
        p = check_solutions(new_parameters, cipher,rnd_string_tmp, new_parameters["sweight"] + 4)
        p *= p
        rectangle_weight = math.log2(p)
        save_str = "cipher:{0}, rounds:{1}, inputDiff:{2}, outputDiff:{3}, boomerang weight:{4}, rectangle weight:{5}, switchStartRound:{6}, SwitchRounds:{7}\n".format(
            cipher.name, r, input_diff, output_diff, params["sweight"] * 2, rectangle_weight, switch_start_round,
            switch_rounds)
        result_file.write(save_str)
        result_file.flush()
        params["sweight"] += 1


def check_solutions(new_parameter, cipher, start_time, max_weight=32):
    max_weight = 32 if max_weight > 32 else max_weight
    sat_logfile = "tmp/satlog-{0}-{1}.tmp".format(cipher.name, start_time)
    prob = 0
    stp_file = "tmp/{}{}-{}.stp".format(cipher.name, "clutesr", start_time)
    while new_parameter["sweight"] < max_weight:
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
            if solutions % 100 == 0:
                print("\tSolutions: {}\r".format(solutions // 2), end="")

        log_file.close()
        if solutions > 0:
            print("\tSolutions: {}".format(solutions // 2))

            assert solutions == search.countSolutionsLogfile(sat_logfile)

            # The encoded CNF contains every solution twice
            solutions //= 2
            prob += math.pow(2, -new_parameter["sweight"]) * solutions
        new_parameter["sweight"] += 1
    return prob


def start_search():
    c = katan32_bct.katan32()
    start_rounds = 89
    end_ends = 120
    while start_rounds <= end_ends:
        task_list = []
        for _ in range(MAX_THREAD):
            #task_list.append(threading.Thread(target=find_single_trail, args=(c, start_rounds, 0, int(start_rounds / 2), 4)))
            task_list.append(multiprocessing.Process(target=find_single_trail, args=(c, start_rounds, 0, int(start_rounds / 2), 4)))
            start_rounds += 1
        for task in task_list:
            task.start()
        for task in task_list:
            task.join()

start_search()