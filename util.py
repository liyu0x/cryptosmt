import os
import numpy as np


def makedirs(dirs: list):
    for dir in dirs:
        if not os.path.exists(dir):
            os.makedirs(dir)


def sand_t(n, rotation=0) -> list:
    if n % 4 != 0:
        return []
    res = [[], [], [], []]
    for i in range(n):
        remainder = i % 4
        res[remainder].append(i)
    res = np.reshape(res, (len(res), len(res[1])))
    if rotation > 0:
        res = np.roll(res, rotation, 1)
    return np.reshape(res, (1, len(res) * len(res[1]))).tolist()[0]


def sand_rot(n, rotation=0) -> list:
    if n % 4 != 0:
        return []
    res = [i for i in range(n)]
    res = np.reshape(res, (4, n // 4))
    if rotation > 0:
        res = np.roll(res, rotation, 1)
    return np.reshape(res, (1, len(res) * len(res[1]))).tolist()[0]
