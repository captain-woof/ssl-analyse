import argparse
import re
from urllib.parse import urlparse
from sslyze import ServerNetworkLocation, ServerScanRequest, ServerScanResult, ServerHostnameCouldNotBeResolved, SslyzeOutputAsJson, ServerScanResultAsJson
from sslyze.scanner.scanner import Scanner
from os import path, mkdir
import datetime
import traceback

def parseTargetString(targetStr):
    """
    Parses a user-provided target string into a (hostname, port) tuple.
    Handles formats: "host", "host:port", "https://host", "https://host:port".
    Returns (hostname, port, original_string) or None if parsing fails.
    """
    targetStr = targetStr.strip()
    if not targetStr:
        return None

    # Use urlparse for URL-like strings
    if targetStr.startswith(("http://", "https://")):
        # Prepend a default scheme if none is present, to help urlparse
        if "://" not in targetStr:
            targetStr = "https://" + targetStr
        parsed = urlparse(targetStr)
        hostname = parsed.hostname
        port = parsed.port or 443
        return (hostname, port, targetStr)

    # Use regex for "host:port" or just "host"
    match = re.match(r"^([^:]+)(?::(\d+))?$", targetStr)
    if match:
        hostname, port_str = match.groups()
        port = int(port_str) if port_str else 443
        return (hostname, port, targetStr)

    return None


def processScanResult(result: ServerScanResult):
    failures = []

    ipAddr = result.server_location.ip_address
    hostname = result.server_location.hostname
    port = result.server_location.port
    scanTarget = f"{ipAddr}:{port} ({hostname if hostname else 'no hostname'})"

    # 1. Certificate Trust and Validity
    try:
        if result.scan_result is None:
            return 

        for certificate in result.scan_result.certificate_info.result.certificate_deployments:
            for validationResult in certificate.path_validation_results:
                if validationResult.was_validation_successful:
                    pass # ALL GOOD
                else:
                    failures.append(validationResult.validation_error)
                    break

        # 2. Insecure Protocol Support (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
        protocols = {
            "SSL 2.0": result.scan_result.ssl_2_0_cipher_suites,
            "SSL 3.0": result.scan_result.ssl_3_0_cipher_suites,
            "TLS 1.0": result.scan_result.tls_1_0_cipher_suites,
            "TLS 1.1": result.scan_result.tls_1_1_cipher_suites,
        }
        for name, res in protocols.items():
            if res and res.result and res.result.accepted_cipher_suites and len(res.result.accepted_cipher_suites) != 0:
                failures.append(f"Insecure protocol supported: {name}")

        # 3. Weak Cipher Suites in Modern Protocols (TLS 1.2, 1.3)
        modern_protocols = {
            "TLS 1.2": result.scan_result.tls_1_2_cipher_suites,
            "TLS 1.3": result.scan_result.tls_1_3_cipher_suites,
        }
        for proto, res in modern_protocols.items():
            if res and res.result:
                for cipher in res.result.accepted_cipher_suites:
                    # Check for common weak cipher keywords
                    if any(weak.lower() in cipher.cipher_suite.name.lower() for weak in ["RC4", "3DES", "MD5", "EXPORT", "NULL"]):
                        failures.append(f"Weak cipher in {proto}: {cipher.cipher_suite.name}")

        # 4. Insecure Session Renegotiation
        reneg_res = result.scan_result.session_renegotiation.result
        if reneg_res and not reneg_res.supports_secure_renegotiation:
            failures.append("Insecure session renegotiation supported")

        # 5. TLS Compression (CRIME vulnerability)
        comp_res = result.scan_result.tls_compression.result
        if comp_res and comp_res.supports_compression:
            failures.append("TLS compression is enabled (CRIME)")

        # 6. Heartbleed Vulnerability
        hb_res = result.scan_result.heartbleed.result
        if hb_res and hb_res.is_vulnerable_to_heartbleed:
            failures.append("Vulnerable to Heartbleed")

        # 7. ROBOT Attack Vulnerability
        robotResult = result.scan_result.robot.result
        if robotResult and "not_vulnerable" not in robotResult.robot_result.lower():
            failures.append(f"ROBOT attack possible ({robotResult.robot_result.name})")

        # Return result for VALID or INVALID result
        if len(failures) == 0: # Everything valid :)
            return ("valid", scanTarget, f"{scanTarget}, VALID")
        else:
            return ("invalid", scanTarget, f"{scanTarget}, INVALID, Issues:{failures}")
        
    except Exception as e:
        traceback.print_exc() # Prints stack trace
        return ("error", scanTarget, f"{scanTarget}, ERROR, {type(e).__name__}: {e}")

def main():
    parser = argparse.ArgumentParser(description="A multi-threaded, exhaustive TLS/SSL scanner with consistent port output.")
    parser.add_argument("-i", "--input-file", required=True, help="File with target hosts, one per line.")
    parser.add_argument("-oV", "--valid-file", help="Output file for hosts with no issues.")
    parser.add_argument("-oI", "--invalid-file", help="Output file for hosts with TLS/SSL issues.")
    parser.add_argument("-oE", "--error-file", help="Output file for hosts that could not be scanned.")
    parser.add_argument("-oD", "--verbose-output-dir", help="Directory to store verbose per-target result in")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads to use")
    parser.add_argument("-v", "--verbose", help="Log each request/response to STDOUT (does not affect output to files)", action="store_true")
    args = parser.parse_args()   

    # Read and parse targets from input file
    scanRequests = []
    try:
        print("[+] Parsing input")
        with open(args.input_file, 'r') as f:
            for targetLine in f:
                target = targetLine.strip()
                if not target:
                    continue
                parsedTarget = parseTargetString(target)
                if parsedTarget:
                    try:
                        scanRequests.append(
                            ServerScanRequest(
                                server_location=ServerNetworkLocation(hostname=parsedTarget[0], port=parsedTarget[1]),
                            )
                        )
                    except ServerHostnameCouldNotBeResolved:
                        pass
                else:
                    print(f"\t{target},ParseError: Could not parse target")
    except FileNotFoundError:
        print(f"FATAL: Input file not found at {args.input_file}")
        return
    

    # Start scan and wait for it to finish
    print(f"[+] Scanning {len(scanRequests)} targets")
    scanner = Scanner(
        concurrent_server_scans_limit=args.threads,
        per_server_concurrent_connections_limit=15
    )
    scanner.queue_scans(scanRequests)

    # Open necessary files
    fileToWriteValid, fileToWriteInvalid, fileToWriteError = None, None, None
    if args.valid_file:
        fileToWriteValid = open(args.valid_file, "w")
    if args.invalid_file:
        fileToWriteInvalid = open(args.invalid_file, "w")
    if args.error_file:
        fileToWriteError = open(args.error_file, "w")

    # Create verbose output folder if needed
    if args.verbose_output_dir is not None:
        try:
            mkdir(args.verbose_output_dir)
        except FileExistsError:
            pass

    # Scan and process results
    timeScanStart = datetime.datetime.now()
    for result in scanner.get_results():
        resultType, scanTarget, resultProcessed = processScanResult(result)
        if args.verbose:
            print(f"\t>> {resultProcessed}")

        # Store summary result
        if resultType == "valid" and fileToWriteValid is not None:
            fileToWriteValid.write(resultProcessed + "\n")
        if resultType == "invalid" and fileToWriteInvalid is not None:
            fileToWriteInvalid.write(resultProcessed + "\n")
        if resultType == "error" and fileToWriteError is not None:
            fileToWriteError.write(resultProcessed + "\n")

        # Store entire result JSON
        if args.verbose_output_dir is not None:
            filename = path.join(args.verbose_output_dir, f"{scanTarget.replace(' ','-')}.json")
            with open(filename, "w") as fileToWriteWholeResult:
                jsonOutput = SslyzeOutputAsJson(
                    server_scan_results=[ServerScanResultAsJson.model_validate(result)],
                    invalid_server_strings=[],  # Not needed here - specific to the CLI interface
                    date_scans_started=timeScanStart,
                    date_scans_completed=datetime.datetime.now(),
                )
                fileToWriteWholeResult.write(jsonOutput.model_dump_json())

    # Close necessary files
    if fileToWriteValid is not None:
        fileToWriteValid.close()
    if fileToWriteInvalid is not None:
        fileToWriteInvalid.close()
    if fileToWriteError is not None:
        fileToWriteError.close()

if __name__ == "__main__":
    main()