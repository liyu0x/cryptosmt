from ciphers import katan48_bct
import multiprocessing
from katan_48_bct_search_task import find_single_trail

MAX_THREAD = 12

MAX_SINGLE_TRAIL_SERACH_LIMIT = 4
MAX_CLUSTER_TRAIL_SERACH_LIMIT = 4

POOL = multiprocessing.Pool(processes=MAX_THREAD)
SWITCH_ROUNDS = 4

if __name__ == '__main__':
    c = katan48_bct.katan48()
    start_rounds = 60
    end_ends = 60
    while start_rounds <= end_ends:
        task_list = []
        for _ in range(MAX_THREAD):
            task_list.append(
                POOL.apply_async(find_single_trail, args=(c, start_rounds, 0, int(start_rounds / 2), SWITCH_ROUNDS)))
            start_rounds += 1
            if start_rounds > end_ends:
                break
    for task in task_list:
            task.get()