# The server side of the exfiltration simulation

Exfiltrated data is captured, optionally decoded and optionally a response is sent to the incoming query.

## Usage
1. Fill in the `RESPONSE_ADDRESS` in `tdns/exfil.py` with the address that should be sent as a response.
2. Run `python3 attacker <profile name>`.
   - See `profiles.py` for a list of default profiles. Feel free to add a new one (for example with a disabled `respond` option).