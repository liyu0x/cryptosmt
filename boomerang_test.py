from ciphers import katan32
from cryptanalysis import search
import os
from parser import parsesolveroutput, stpcommands

max_num = 0
char = None


def find_has_many_solutions():
    global max_num
    global char
    katan = katan32.katan32()
    params = {"rounds": 40,
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
              "offset": 0}

    stp_file = "tmp/test.stp"
    save_file = "result/a.txt"

    result_file = open(save_file, 'a')

    extra_command = ""
    while params["sweight"] < 32:
        weight = params["sweight"]
        katan.createSTP(stp_file, params)
        params["sweight"] = weight + 1
        result = ""
        if params["boolector"]:
            result = search.solveBoolector(stp_file)
        else:
            result = search.solveSTP(stp_file)
        if result.startswith("Valid"):
            print("No trails, weight:{0}".format(weight))
            extra_command = ""
            continue
        characteristic = ""
        if params["boolector"]:
            characteristic = parsesolveroutput.getCharBoolectorOutput(
                result, katan, params["rounds"])
        else:
            characteristic = parsesolveroutput.getCharSTPOutput(
                result, katan, params["rounds"])

        if characteristic != "":
            characteristic.printText()
            solutions, max_w = check_solutions(characteristic, params, weight, katan)
            max_num = solutions
            char = characteristic
            result_file.write("in:{0},out:{1},weight:{2},solutions:{3}\n".format(characteristic.getInputDiff(),
                                                                                 characteristic.getOutputDiff(), max_w,
                                                                                 solutions))
            params["sweight"] = weight
            params["blockedCharacteristics"].append(char)


def check_solutions(characteristic, parameters, weight, cipher):
    max_w = 0
    max_solutions = 0
    parameters["fixedVariables"].clear()
    parameters["fixedVariables"]["X0"] = characteristic.getInputDiff()
    parameters["fixedVariables"]["X{}".format(parameters["rounds"])] = characteristic.getOutputDiff()
    parameters["sweight"] = weight
    sat_logfile = "tmp/satlog{}.tmp".format(1234)
    # Search until optimal weight + wordsize/8
    solutions = 0

    while parameters["sweight"] < weight + 3:
        if os.path.isfile(sat_logfile):
            os.remove(sat_logfile)
        stp_file = "tmp/{}{}-{}.stp".format(cipher.name, "test", "12342")
        cipher.createSTP(stp_file, parameters)

        # Start solver
        sat_process = search.startSATsolver(stp_file)
        log_file = open(sat_logfile, "w")

        # Find the number of solutions with the SAT solver
        print("Finding all trails of weight {}".format(parameters["sweight"]))

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
        print("\tSolutions: {}".format(solutions // 2))

        assert solutions == search.countSolutionsLogfile(sat_logfile)

        # The encoded CNF contains every solution twice
        solutions //= 2
        if solutions > max_solutions:
            max_solutions = solutions
            max_w = parameters["sweight"]
        parameters["sweight"] += 1
    return max_solutions, max_w


find_has_many_solutions()
