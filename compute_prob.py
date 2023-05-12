import math


def compute():
    file = open("result/a.txt", "r")
    res = []
    line = file.readline()
    res.append(line)
    while line:
        line = file.readline()
        res.append(line)
    ress = []
    for l in res:
        if l == "":
            break
        l = l.replace("\n", "")
        ls = l.split(",")
        r = []
        r.append(int(ls[0].split(":")[1]))
        r.append(int(ls[3].split(":")[1]))
        r.append(int(ls[4].split(":")[1]))
        ress.append(r)

    final_res = {}
    for r in ress:
        if r[0] not in final_res:
            final_res[r[0]] = 0
        diff_prob = final_res[r[0]]
        diff_prob += math.pow(2, -r[1]) * r[2]
        final_res[r[0]] = diff_prob
    for i in range(35, 55):
        print("{0}:{1}".format(i, str(math.log(final_res[i]*final_res[i], 2))))


compute()
