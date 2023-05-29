from ciphers import katan64_bct
import multiprocessing
from katan_64_bct_search_task import find_single_trail

MAX_THREAD = 4

SWITCH_ROUNDS = 7

S_WEIGHT = {57: 39,
            58: 39,
            59: 40,
            60: 41}

POOL = multiprocessing.get_context("fork").Pool(MAX_THREAD)

if __name__ == '__main__':
    c = katan64_bct.katan64()
    start_rounds = 57
    end_ends = 70
    while start_rounds <= end_ends:
        task_list = []
        for _ in range(MAX_THREAD):
            sweight = 36
            if start_rounds in S_WEIGHT:
                sweight = S_WEIGHT[start_rounds]+1
            task_list.append(
                POOL.apply_async(find_single_trail,
                                 args=(c, start_rounds, 0, int(start_rounds / 2), SWITCH_ROUNDS, sweight)))
            start_rounds += 1
            if start_rounds > end_ends:
                break
        for task in task_list:
            task.get()
