from ciphers import katan64_bct
import multiprocessing
from katan_64_bct_search_task import find_single_trail

MAX_THREAD = 4

SWITCH_ROUNDS = 7

S_WEIGHT = {58: 35,
            60: 36,
            57: 35,
            59: 35}

POOL = multiprocessing.get_context("fork").Pool(MAX_THREAD)

if __name__ == '__main__':
    c = katan64_bct.katan64()
    start_rounds = 57
    end_ends = 70
    while start_rounds <= end_ends:
        task_list = []
        for _ in range(MAX_THREAD):
            task_list.append(
                POOL.apply_async(find_single_trail,
                                 args=(c, start_rounds, 0, int(start_rounds / 2), SWITCH_ROUNDS, 31)))
            start_rounds += 1
            if start_rounds > end_ends:
                break
        for task in task_list:
            task.get()
