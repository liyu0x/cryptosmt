from argparse import ArgumentParser, RawTextHelpFormatter


def main():
    """
    Parse the arguments and start the request functionality with the provided
    parameters.
    """
    parser = ArgumentParser(description="This tool finds the best differential"
                                        "trail in a cryptopgrahic primitive"
                                        "using STP and CryptoMiniSat.",
                            formatter_class=RawTextHelpFormatter)

    parser.add_argument('--cipher', nargs=1, help="Options: simon32, katan32")
    parser.add_argument('--sweight', nargs=1, type=int,
                        help="Starting weight for the trail search.")
    parser.add_argument('--endweight', nargs=1, type=int,
                        help="Stop search after reaching endweight.")
    parser.add_argument('--rounds', nargs=1, type=int,
                        help="The number of rounds for the cipher")
    parser.add_argument('--wordsize', nargs=1, type=int,
                        help="Wordsize used for the cipher.")
    parser.add_argument('--blocksize', nargs=1, type=int,
                        help="Blocksize used for the cipher.")
    parser.add_argument('--nummessages', nargs=1, type=int,
                        help="Number of message blocks.")
    parser.add_argument('--mode', nargs=1, type=int,
                        choices=[0, 1, 2, 3, 4], help=
                        "0 = search characteristic for fixed round\n"
                        "1 = search characteristic for all rounds starting at"
                        "the round specified\n"
                        "2 = search all characteristic for a specific weight\n"
                        "3 = used for key recovery\n"
                        "4 = determine the probability of the differential\n")
    parser.add_argument('--timelimit', nargs=1, type=int,
                        help="Set a timelimit for the search in seconds.")
    parser.add_argument('--iterative', action="store_true",
                        help="Only search for iterative characteristics")
    parser.add_argument('--boolector', action="store_true",
                        help="Use boolector to find solutions")
    parser.add_argument('--inputfile', nargs=1, help="Use an yaml input file to"
                                                     "read the parameters.")
    parser.add_argument('--dot', nargs=1, help="Print the trail in .dot format.")
    parser.add_argument('--latex', nargs=1, help="Print the trail in .tex format.")

    # Parse command line arguments and construct parameter list.
    args = parser.parse_args()
    params = loadparameters(args)

    # Check if enviroment is setup correctly.
    checkenviroment()

    # Start the solver
    startsearch(params)


if __name__ == '__main__':
    main()
