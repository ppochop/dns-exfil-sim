# The client side of the exfiltration simulation.

Data is generated and transported to the server using one of the implemented exfiltration vectors or all of them at once.

## Usage
1. Fill in the `DOMAIN` and `RECORD_TYPE` in `tdns/exfil.py`.
2. Fill in the `ATTACKER_IP` in `profiles.py`. (Required for `ebury`.)
3. Run `python3 target <profile> <profile_number>`.
    - Run from within the parent directory of this file's directory.
    - See the help or `profiles.py` for information about profiles.
    - See `tdns/exfil.py` for different configuration options in each profile.