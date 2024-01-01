def compute():
    start_round = 56
    end_round = 62
    switch_rounds = 3
    for r in range(start_round, end_round + 1):
        switch_start_round = int(r / 2) - int(switch_rounds / 2)
        print("rounds:{0}, E1:{1}, E0:{2}".format(r,
                                                  r - (switch_start_round + switch_rounds), switch_start_round))


compute()
