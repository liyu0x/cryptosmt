import os
import numpy as np


def makedirs(dirs: list):
    for dir in dirs:
        if not os.path.exists(dir):
            os.makedirs(dir)


def sand_t(n, rotation=0):
    if n % 4 != 0:
        return
    res = [[], [], [], []]
    for i in range(n - 1, -1, -1):
        remainder = i % 4
        res[remainder].append(i)
    res.reverse()
    res = np.reshape(res, (len(res), len(res[1])))

    if rotation > 0:
        res = np.roll(res, rotation, 1)
    return res
