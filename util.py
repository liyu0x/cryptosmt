import os
from ciphers import simonbct_v2


def makedirs(dirs: list):
    for dir in dirs:
        if not os.path.exists(dir):
            os.makedirs(dir)


def switch_validation_checking(switch_list, cipher: simonbct_v2):
    error = 0
    count = 0
    for input_switch in switch_list['input']:
        for output_switch in switch_list['output']:
            left_input = int(input_switch[0], 16)
            right_output = int(output_switch[0], 16)
            left_input_arr = [i for i in bin(left_input)[2:]]
            right_output_arr = [i for i in bin(right_output)[2:]]
            left_input_alpha = cipher.left_rotate_array(left_input_arr, cipher.rot_alpha)
            left_input_beta = cipher.left_rotate_array(left_input_arr, cipher.rot_beta)
            right_output_alpha = cipher.left_rotate_array(right_output_arr, cipher.rot_alpha)
            right_output_beta = cipher.left_rotate_array(right_output_arr, cipher.rot_beta)
            count += 1
            left_a = int(''.join(left_input_alpha), 2)
            left_b = int(''.join(left_input_beta), 2)
            right_a = int(''.join(right_output_alpha), 2)
            right_b = int(''.join(right_output_beta), 2)
            if left_a & right_b != left_b & right_a:
                error += 1

    print()
