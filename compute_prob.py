import math


def compute_a():
    file = open("result/a.txt", "r")
    data = []
    line = file.readline()
    data.append(line)
    while line:
        line = file.readline()
        data.append(line)

    results = {}
    for d in data:
        if d == "":
            break
        d = d.replace("\n", "")
        ls = d.split(",")
        r = []
        r.append(int(ls[0].split(":")[1]))
        r.append(int(ls[3].split(":")[1]))
        r.append(int(ls[4].split(":")[1]))
        group_list = []
        if r[0] not in results:
            group_list = []
            results[r[0]] = group_list
        group_list = results[r[0]]
        group_list.append(r)

    final_res = {}
    for rounds in results:
        diff_prob = 0
        for result in results[rounds]:
            diff_prob += math.pow(2, -result[1]) * result[2]
        final_res[rounds] = diff_prob
        print("Rounds:{0}, Probability:{1}".format(rounds, str(diff_prob)))

def compute_b():
    file = open("result/b.txt", "r")
    data = []
    line = file.readline()
    data.append(line)
    while line:
        line = file.readline()
        data.append(line)

    results = {}
    for d in data:
        if d == "":
            break
        d = d.replace("\n", "")
        ls = d.split(",")
        r = []
        r.append(int(ls[0].split(":")[1]))
        r.append(int(ls[2].split(":")[1]))
        r.append(int(ls[3].split(":")[1]))
        group_list = []
        if r[0] not in results:
            group_list = []
            results[r[0]] = group_list
        group_list = results[r[0]]
        group_list.append(r)

    final_res = {}
    for rounds in results:
        diff_prob = 0
        for result in results[rounds]:
            diff_prob += math.pow(2, -result[1]) * result[2]
        final_res[rounds] = diff_prob
        print("Rounds:{0}, Probability:{1}".format(rounds, str(diff_prob)))


compute_b()