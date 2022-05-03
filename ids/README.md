# Anomaly-based detection script

The script is my humble attempt at implementing the mechanism described by [Nadler et al.](https://www.sciencedirect.com/science/article/pii/S0167404818304000). It tries to detect data exfiltration through the DNS protocol in a domain-based approach -> the result is a list of domains that are considered suspicious by the script.
The script works with `.log` files created by [`passivedns`](https://github.com/gamelinux/passivedns).

## Usage

### Live detection
`sniffer.py -l "/var/log/passivedns.log" -c "0.001" -d 5 -n 10`
- Actively reads the `passivedns`' log file every `5` minutes, all entries from those `5` minutes are collected into a sliding window of those collections.
- The window contains `10` of these collections and evaluation is performed on this window. (That means every `5` minutes a new evaluation occurs for the previous `5*10` minutes.)

### Offline detection
`sniffer.py -b -r 10 -p -l "captured_traffic/logs/" -n 5`
- Reads at most `5` `passivedns` log(s) located at `captured_traffic/logs`.
- The data from the logs will form a window which is evaluated.
- This process will repeat itself `10` times.
- A barplot is generated showing the detected domains and the number of times they were detected in those `10` runs.

### Notes
- The `-t/-m` arguments provide an option to train a model or use a trained model. Useful if we want to look for anomalies using a "baseline" from a different traffic than the one that's being evaluated.
- In offline mode, the "sliding" window (in offline evaluation the window won't actually be sliding as it won't change) can be represented using a single `.log` file or a number of these files specified by the `-n` option.
- The `-d` option corresponds to the λ parameter in the [article](https://www.sciencedirect.com/science/article/pii/S0167404818304000).
- The `-n` option corresponds to the n<sub>s</sub> parameter in the [article](https://www.sciencedirect.com/science/article/pii/S0167404818304000).