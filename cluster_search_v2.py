from argparse import ArgumentParser, RawTextHelpFormatter
import yaml
from ciphers import katan32bct, simonbct_v2, katan48bct
import time
import util
import random
from cryptanalysis import search
import copy
import math
import uuid
import os
from config import USE_SHARP
import re

START_WEIGHT = {"simon32": {10: 13, 13: 24}}

CIPHER_MAPPING = {"katan32BCT": katan32bct.katan32(),
                  "simon": simonbct_v2.SimonCipher(),
                  "katan48BCT": katan48bct.katan48()}

RESULT_DIC = {'simon': "simon_result/", "katan32BCT": "katan32_result/", "katan48BCT": "katan48_result/"}
TEMP_DIC = "tmp/"


def check_solutions(new_parameter, cipher, threshold, cluster_count):
    print("Start Cluster:{0}, rounds:{1}, weight:{2}".format(new_parameter["position"], new_parameter["rounds"],
                                                             new_parameter["sweight"]))
    new_parameter['countered_trails'].clear()
    prob = 0
    start_time = str(uuid.uuid4())
    stp_file = TEMP_DIC + "{}{}-{}.stp".format(cipher.name, "clutesr", start_time)
    last_weight = 0
    count = 0
    cluster_counter = 0
    new_parameter['cluster'] = 1
    new_parameter['sweight'] = 0
    while count < threshold and cluster_counter < cluster_count:
        cluster_counter += 1
        cipher.createSTP(stp_file, new_parameter)

        # Start solver
        sat_process = search.startSATsolver(stp_file)

        # Find the number of solutions with the SAT solver
        print("Finding all trails of weight {}".format(new_parameter["sweight"]))

        # Watch the process and count solutions
        solutions = 0
        while sat_process.poll() is None:
            lines = sat_process.stdout.readlines()
            if USE_SHARP == 1:
                done = False
                for line in lines:
                    if "exact arb" in line.decode("utf-8"):
                        done = True
                if not done:
                    continue
                line = lines[len(lines) - 1].decode("utf-8")
                pattern = re.compile('\d+')
                solutions += int(pattern.search(line).group())
            else:
                for line in lines:
                    if "s SATISFIABLE" in line.decode("utf-8"):
                        solutions += 1
        if solutions > 0:
            print("\tSolutions: {}".format(solutions / 2))
            # assert solutions == search.countSolutionsLogfile(sat_logfile)
            solutions /= 2
            new_p = math.pow(2, -new_parameter["sweight"]) * (solutions / 2)
            prob += new_p
            new_weight = int(math.log2(prob))
            report_str = "boomerang weight: {0}, rectangle weight:{1}".format(-new_parameter['sweight'],
                                                                              math.log2(new_p))
            print(report_str)
            # cipher.get_cluster_params(new_parameter, new_p, prob)
        else:
            new_parameter['sweight'] += 1
            continue

        new_parameter['sweight'] += 1
        # print("Cluster Searching Stage|Current Weight:{0}".format(new_weight))
        if new_weight == last_weight:
            count += 1
        else:
            last_weight = new_weight
            count = 0
    return prob


def find_single_trail(cipher, r, lunch_arg):
    result_dic = RESULT_DIC[cipher.name]
    task_start_time = time.time()
    valid_count = 0
    save_file = result_dic + "{0}-{1}_v2.txt".format(cipher.name, r)
    save_list_file = result_dic + "{0}-{1}-LIST_v2.txt".format(cipher.name, r)
    result_file = open(save_file, "w")
    result_list_file = open(save_list_file, 'w')
    params = copy.deepcopy(lunch_arg)
    each_round_max_valid = int(lunch_arg['eachRoundMaxValid'])
    each_round_max_time = int(lunch_arg['eachRoundMaxTime']) * 3600
    rnd_string_tmp = "%030x" % random.randrange(16 ** 30)
    stp_file = TEMP_DIC + "{0}-{1}-{2}.stp".format(cipher.name, rnd_string_tmp, r)
    while valid_count <= each_round_max_valid and time.time() - task_start_time <= each_round_max_time:
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
        characteristic.printText()

        switch_list, switch_prob = find_all_switch(cipher, stp_file, copy.deepcopy(params), characteristic.getData())

        # Cluster Search
        new_parameters = copy.deepcopy(params)

        new_parameters["blockedCharacteristics"].clear()
        new_parameters["fixedVariables"].clear()

        new_parameters['switchStartRound'] = -1
        top_param = copy.deepcopy(new_parameters)
        top_param['switch_list'] = switch_list
        top_param['position'] = 'top'
        cipher.create_cluster_parameters(top_param, characteristic)
        w1 = check_solutions(top_param, cipher, lunch_arg['threshold'], lunch_arg['cluster_count'])

        bottom_param = copy.deepcopy(new_parameters)
        bottom_param['position'] = 'bottom'
        bottom_param['switch_list'] = switch_list
        cipher.create_cluster_parameters(bottom_param, characteristic)
        w2 = check_solutions(bottom_param, cipher, lunch_arg['threshold'], lunch_arg['cluster_count'])

        switch_len = len(switch_list['input'])

        prob = math.pow(w1 + w2, 2) * switch_prob
        # new_parameters["mode"] = 4

        if prob > 0:
            rectangle_weight = math.log2(prob)
        else:
            rectangle_weight = -9999

        input_diff, switch_input, switch_output, output_diff = cipher.get_diff_hex(params, characteristic)

        save_str = "inputDiff:{0}, outputDiff:{1}, boomerang weight:{2}, rectangle weight:{3}, switch_len:{4}\n".format(
            input_diff,
            output_diff,
            -params[
                'sweight'] * 2,
            rectangle_weight, switch_len)

        result_file.write(save_str)
        result_file.flush()
        save_str = "{0},{1},{2},{3},{4},{5},{6},{7}\n".format(input_diff, switch_input, switch_output, output_diff,
                                                              params["rounds"],
                                                              -params['sweight'], rectangle_weight, switch_len)
        result_list_file.write(save_str)
        result_list_file.flush()
        if rectangle_weight >= -params['wordsize']:
            valid_count += 1
        print("MAX PROB:{0}, INPUT:{1}, OUTPUT:{2}".format(rectangle_weight, input_diff, output_diff))
        # params["sweight"] += 1
        params["countered_trails"].append(characteristic)


def find_all_switch(cipher, stp_file, param, trails):
    print("start search all valid boomerang switches")
    r = param['rounds']
    switch_list = {"input": [], "output": []}
    # input diff
    input_diff_l = trails[0][0]
    input_diff_r = trails[0][1]

    # output diff
    output_diff_l = trails[r][2]
    output_diff_r = trails[r][3]
    param['test'] = ''
    param["fixedVariables"]["XL0"] = input_diff_l
    param["fixedVariables"]["XR0"] = input_diff_r

    param["fixedVariables"]["YL{}".format(r)] = output_diff_l
    param["fixedVariables"]["YR{}".format(r)] = output_diff_r
    while True:
        cipher.createSTP(stp_file, param)
        result = search.solveSTP(stp_file)
        if not search.foundSolution(result):
            print(
                "Rounds:{1}, No trails, weight:{0}, switch:{2}\n".format(
                    param["sweight"], param["rounds"], len(switch_list['input'])
                )
            )
            break
        characteristic = search.parsesolveroutput.getCharSTPOutput(result, cipher, param["rounds"])
        trails = characteristic.getData()
        input_switch_l = trails[param['em_start_num']][0]
        input_switch_r = trails[param['em_start_num']][1]
        output_switch_l = trails[param['em_end_num']][2]
        output_switch_r = trails[param['em_end_num']][3]
        switch_list['input'].append([input_switch_l, input_switch_r])
        switch_list['output'].append([output_switch_l, output_switch_r])

        command = "ASSERT(NOT("

        str1 = "(BVXOR(XL{0},{1})|BVXOR(XR{0}, {2}) | BVXOR(YL{3}, {4}) | BVXOR(YR{3}, {5}))".format(
            param['em_start_num'], input_switch_l, input_switch_r, param['em_end_num'], output_switch_l,
            output_switch_r)
        command += str1
        command += "&"
        command = command[:-1]
        command += "=0x0000));\n"
        param["test"] += command

    prob = util.switch_validation_checking(switch_list, cipher)
    return switch_list, prob


def start_search(lunch_arg):
    cipher_name = lunch_arg['cipher']
    cipher = CIPHER_MAPPING[cipher_name]
    util.makedirs([RESULT_DIC[cipher_name], TEMP_DIC])
    start_round = lunch_arg['startRound']
    end_round = lunch_arg['endRound']
    end_round = start_round + 1 if end_round == -1 else end_round
    switch_rounds = lunch_arg['switchRounds']
    params = copy.deepcopy(lunch_arg)
    for r in range(start_round, end_round):
        start_weight = 0
        for i in range(r, -1, -1):
            if i in START_WEIGHT:
                start_weight = START_WEIGHT[i]
                break
        switch_start_round = int(r / 2) - int(switch_rounds / 2)
        params['rounds'] = r
        params['switchStartRound'] = switch_start_round
        find_single_trail(cipher, r, params)


def loadparameters(args):
    """
    Get parameters from the argument list and inputfile.
    """
    # Load default values
    params = {"cipher": "simon",
              "startRound": 5,
              "endRound": -1,
              "switchRounds": 4,
              "threshold": 6,
              "eachRoundMaxTime": 60 * 60 * 5,
              "eachRoundMaxValid": 2,
              "wordsize": 16,
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
              "blockedCharacteristics": []}

    # Check if there is an input file specified
    if args.inputfile:
        with open(args.inputfile[0], 'r') as input_file:
            doc = yaml.load(input_file, Loader=yaml.Loader)
            params.update(doc)
            if "fixedVariables" in doc:
                fixed_vars = {}
                for variable in doc["fixedVariables"]:
                    fixed_vars = dict(list(fixed_vars.items()) +
                                      list(variable.items()))
                params["fixedVariables"] = fixed_vars

    return params


def main():
    parser = ArgumentParser(description="This tool finds the best differential"
                                        "trail in a cryptopgrahic primitive"
                                        "using STP and CryptoMiniSat.",
                            formatter_class=RawTextHelpFormatter)

    parser.add_argument('--inputfile', nargs=1, help="Use an yaml input file to"
                                                     "read the parameters.")

    args = parser.parse_args()
    params = loadparameters(args)
    start_search(params)


if __name__ == '__main__':
    main()
