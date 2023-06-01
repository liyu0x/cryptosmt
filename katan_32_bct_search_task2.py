import random
from cryptanalysis import search
import os
import math

def check_solutions(new_parameter, cipher, weight):
    new_parameter['sweight'] += weight
    start_time = "%030x" % random.randrange(16 ** 30)
    sat_logfile = "tmp/satlog-{0}-{1}.tmp".format(cipher.name, start_time)
    prob = 0
    stp_file = "tmp/{}{}-{}.stp".format(cipher.name, "clutesr", start_time)
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
    return prob

