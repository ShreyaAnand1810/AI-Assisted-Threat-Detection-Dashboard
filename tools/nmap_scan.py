import subprocess
import shutil
import ipaddress
import re


def is_valid_target(target):
    """
    Validate IP address or hostname.
    """

    target = target.strip()

    if target == "":
        return False

    # Check IP
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Check hostname/domain
    hostname_pattern = re.compile(
        r"^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+$"
    )

    return bool(hostname_pattern.match(target))


def parse_output(output):
    """
    Convert raw Nmap output into structured data.
    """

    open_ports = []

    for line in output.splitlines():

        line = line.strip()

        if "/tcp" in line or "/udp" in line:

            parts = line.split()

            if len(parts) >= 3:

                open_ports.append({
                    "port": parts[0],
                    "state": parts[1],
                    "service": parts[2]
                })

    return open_ports


def run_nmap_scan(target):

    target = target.strip()

    if not is_valid_target(target):

        return {
            "status": "error",
            "message": "Invalid IP address or hostname."
        }

    nmap_path = shutil.which("nmap")

    if nmap_path is None:

        return {
            "status": "error",
            "message": (
                "Nmap is not installed or not added to PATH."
            )
        }

    try:

        command = [

            nmap_path,

            "-sV",      # Version Detection

            "-F",       # Fast Scan

            "--open",   # Show only open ports

            target

        ]

        result = subprocess.run(

            command,

            capture_output=True,

            text=True,

            timeout=60

        )

        if result.returncode != 0:

            return {

                "status": "error",

                "message": result.stderr.strip()

            }

        raw_output = result.stdout

        ports = parse_output(raw_output)

        return {

            "status": "success",

            "target": target,

            "total_open_ports": len(ports),

            "ports": ports,

            "raw_output": raw_output

        }

    except subprocess.TimeoutExpired:

        return {

            "status": "error",

            "message": "Scan timed out."

        }

    except Exception as e:

        return {

            "status": "error",

            "message": str(e)

        }