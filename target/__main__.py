from sys import argv
from asyncio import run
import profiles

HELP = """
USAGE:
    python client <vector> <profile_number>

    Check client/profiles.py for available profiles. Add more if needed.
"""

name = argv[1]
profile_num = argv[2]

profile = f"{name}_{profile_num}"

if profile not in dir(profiles):
    print("Profile not found.")
    print(HELP)
    print(profiles.NUMBERS_MEANING)
    exit(1)

vec = profiles.__getattribute__(profile)()

run(vec())