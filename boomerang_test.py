from ciphers import katan32
from cryptanalysis import search
import os
from parser import parsesolveroutput, stpcommands
import random
import time
import copy


def find_has_many_solutions(param):
    cipher = katan32.katan32()
    params = {
        "rounds": param,
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
        "offset": 0,
    }

    save_file = "result/a.txt"

    result_file = open(save_file, "a+")

    rnd_string_tmp = "%030x" % random.randrange(16**30)

    # find all characteritics with specify weight.
    while params["sweight"] < 32:
        stp_file = "tmp/{}{}.stp".format(cipher.name, rnd_string_tmp)
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
            params["blockedCharacteristics"].clear()
            continue
        characteristic = ""
        if params["boolector"]:
            characteristic = parsesolveroutput.getCharBoolectorOutput(
                result, cipher, params["rounds"]
            )
        else:
            characteristic = parsesolveroutput.getCharSTPOutput(
                result, cipher, params["rounds"]
            )
        check_solutions(characteristic, params, params["sweight"], cipher, result_file)
        params["blockedCharacteristics"].append(characteristic)


# find all solutions with specify weight, X0, X[rounds]
def check_solutions(characteristic, parameters, weight, cipher, result_file):
    new_parameter = copy.deepcopy(parameters)
    new_parameter["fixedVariables"].clear()
    new_parameter["blockedCharacteristics"].clear()
    new_parameter["fixedVariables"]["X0"] = characteristic.getInputDiff()
    new_parameter["fixedVariables"][
        "X{}".format(new_parameter["rounds"])
    ] = characteristic.getOutputDiff()
    new_parameter["sweight"] = weight
    sat_logfile = "tmp/satlog{}.tmp".format(1234)
    # Search until optimal weight + wordsize/8

    while new_parameter["sweight"] < 32:
        if os.path.isfile(sat_logfile):
            os.remove(sat_logfile)
        stp_file = "tmp/{}{}-{}.stp".format(cipher.name, "test", "12342")
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
            result_file.write(
                "rounds:{4},in:{0},out:{1},weight:{2},solutions:{3}\n".format(
                    characteristic.getInputDiff(),
                    characteristic.getOutputDiff(),
                    new_parameter["sweight"],
                    solutions,
                    new_parameter["rounds"],
                )
            )
        new_parameter["sweight"] += 1
    result_file.flush()


for i in range(35, 55):
    find_has_many_solutions(i)
