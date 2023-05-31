from ciphers import simon
import multiprocessing
from simon_bct_search_task import find_single_trail

MAX_THREAD = 4

MAX_SINGLE_TRAIL_SERACH_LIMIT = 4
MAX_CLUSTER_TRAIL_SERACH_LIMIT = 4
SWITCH_ROUNDS = 1
WORDSIZE = 16

POOL = multiprocessing.Pool(processes=MAX_THREAD)


if __name__ == '__main__':
    c = simon.SimonCipher()
    c.name = "simon32"
    start_rounds = 13
    end_ends = 25
    while start_rounds <= end_ends:
        task_list = []
        for _ in range(MAX_THREAD):
            task_list.append(
                POOL.apply_async(find_single_trail, args=(c, start_rounds, 0, int(start_rounds / 2), SWITCH_ROUNDS,0)))
            start_rounds += 1
            if start_rounds > end_ends:
                break
        for task in task_list:
            task.get()
