# Installing

```
pip3 install -r requirements.txt
```

# Usage

```
usage: main.py [-h] -i INPUT_FILE [-oV VALID_FILE] [-oI INVALID_FILE] [-oE ERROR_FILE] [-oD VERBOSE_OUTPUT_DIR] [-t THREADS] [-v]

A multi-threaded, exhaustive TLS/SSL scanner with consistent port output.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_FILE, --input-file INPUT_FILE
                        File with target hosts, one per line.
  -oV VALID_FILE, --valid-file VALID_FILE
                        Output file for hosts with no issues.
  -oI INVALID_FILE, --invalid-file INVALID_FILE
                        Output file for hosts with TLS/SSL issues.
  -oE ERROR_FILE, --error-file ERROR_FILE
                        Output file for hosts that could not be scanned.
  -oD VERBOSE_OUTPUT_DIR, --verbose-output-dir VERBOSE_OUTPUT_DIR
                        Directory to store verbose per-target result in
  -t THREADS, --threads THREADS
                        Number of concurrent threads to use
  -v, --verbose         Log each request/response to STDOUT (does not affect output to files)
```

# Example

```
python3 main.py -i test_targets.txt -t 10 -oD out -oV valid.txt -oI invalid.txt -oE error.txt -v
```