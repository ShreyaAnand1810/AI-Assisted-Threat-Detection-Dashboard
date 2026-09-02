import subprocess
import shutil


def get_security_report(target="127.0.0.1"):

    nmap_path = shutil.which("nmap")

    if nmap_path is None:
        nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"

    try:

        result = subprocess.run(
            [nmap_path, "-F", "-sV", target],
            capture_output=True,
            text=True,
            timeout=60
        )

        output = result.stdout

        critical = 0
        high = 0
        medium = 0
        low = 0

        recommendations = []
        findings = []

        for line in output.splitlines():

            line = line.strip()

            if "/tcp" not in line:
                continue

            parts = line.split()

            if len(parts) < 3:
                continue

            port = parts[0]
            state = parts[1]
            service = parts[2].lower()

            findings.append({
                "Port": port,
                "State": state,
                "Service": service
            })

            # -----------------------
            # Risk Analysis
            # -----------------------

            if service == "telnet":
                critical += 1
                recommendations.append(
                    "Disable Telnet immediately and use SSH."
                )

            elif service in ["ftp", "mysql", "microsoft-ds"]:
                high += 1

                if service == "ftp":
                    recommendations.append(
                        "Replace FTP with SFTP/FTPS."
                    )

                elif service == "mysql":
                    recommendations.append(
                        "Restrict MySQL access using firewall."
                    )

                elif service == "microsoft-ds":
                    recommendations.append(
                        "Restrict SMB access and disable SMBv1."
                    )

            elif service in ["http", "msrpc"]:
                medium += 1

                if service == "http":
                    recommendations.append(
                        "Use HTTPS instead of HTTP."
                    )

                else:
                    recommendations.append(
                        "Restrict RPC access to trusted hosts."
                    )

            else:
                low += 1
                recommendations.append(
                    f"Review service running on {port}."
                )

        if len(recommendations) == 0:
            recommendations.append("No major issues detected.")

        recommendations = list(dict.fromkeys(recommendations))

        return {

            "Target": target,

            "Critical": critical,

            "High": high,

            "Medium": medium,

            "Low": low,

            "Open Ports": findings,

            "Recommendations": recommendations

        }

    except Exception as e:

        return {
            "Error": str(e)
        }