import random

a = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0]
b = [8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7]

target_index = random.randint(0, 15)

encryption_process = [target_index]

while True:
    new_target = []
    for t in encryption_process:
        n_a = a.index(t)
        n_b = b.index(t)
        