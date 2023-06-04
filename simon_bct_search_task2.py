from cryptanalysis import search
import os
import math
import uuid

def check_solutions(new_parameter, cipher, start_weight, end_weight):
    new_parameter['sweight'] = start_weight
    start_time = str(uuid.uuid4())
    sat_logfile = "tmp/satlog-{0}-{1}.tmp".format(cipher.name, start_time)
    prob = 0
    stp_file = "tmp/{}{}-{}.stp".format(cipher.name, "clutesr", start_time)
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
            #if solutions % 100 == 0:
                #print("\t Rounds: {1}, Wedight: {2}, Solutions: {0}\r".format(solutions // 2, new_parameter['rounds'],new_parameter['sweight']), end="")

        log_file.close()
        if solutions > 0:
            print("\tSolutions: {}".format(solutions // 2))

            assert solutions == search.countSolutionsLogfile(sat_logfile)

            # The encoded CNF contains every solution twice
            solutions //= 2
            prob += math.pow(2, -new_parameter["sweight"]*2) * solutions
        new_parameter['sweight'] += 1
    return prob

