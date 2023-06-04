from ciphers import katan32_bct, katan48_bct, katan64_bct, simonbct
import multiprocessing
from parallel_task import find_single_trail
import sys

MAX_THREAD = 4

SWITCH_ROUNDS = 1

KATAN32_SETTINGS = {"cipher": katan32_bct.katan32(), "switch_rounds": 4,"wordsize": 32}
KATAN48_SETTINGS = {"cipher": katan48_bct.katan48(), "switch_rounds": 6,"wordsize": 48}
KATAN64_SETTINGS = {"cipher": katan64_bct.katan64(), "switch_rounds": 7,"wordsize": 64}
SIMON32_SETTINGS = {"cipher": simonbct.SimonCipher(), "switch_rounds": 1, "wordsize": 16}

POOL = multiprocessing.get_context("fork").Pool(MAX_THREAD)

if __name__ == '__main__':
    args = sys.argv
    if len(args) == 1:
        print("Please setting a cipher")
        exit(0)
    c = simonbct.SimonCipher()
    start_rounds = 5
    end_ends = 20
    while start_rounds <= end_ends:
        task_list = []
        for _ in range(MAX_THREAD):
            task_list.append(
                POOL.apply_async(find_single_trail,
                                 args=(c, start_rounds, 0, int(start_rounds / 2), SWITCH_ROUNDS, 16)))
            start_rounds += 1
            if start_rounds > end_ends:
                break
        for task in task_list:
            task.get()
