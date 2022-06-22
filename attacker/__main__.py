from sys import argv

import profiles

HELP = """
USAGE:
    python attacker <profile>

    Check attacker/profiles.py for available profiles. Add more if needed.
"""


profile = argv[1]

if profile not in dir(profiles):
    print("Profile not found.")
    print(HELP)
    exit(1)

vec = profiles.__getattribute__(profile)()
vec()
