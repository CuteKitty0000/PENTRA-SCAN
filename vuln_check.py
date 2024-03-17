import subprocess
import psutil
import logging
import pyvas
from vuln_info import vulnerabilities

# Set up logging
logging.basicConfig(filename='security_assessment.log', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def is_defender_running():
    try:
        return any("MsMpEng.exe" in proc.name() for proc in psutil.process_iter())
    except Exception as e:
        logging.error(f"Error checking Windows Defender: {e}")
        return False

def is_firewall_enabled():
    try:
        output = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        return "Status: active" in output.stdout
    except Exception as e:
        logging.error(f"Error checking firewall status: {e}")
        return False

def check_vulnerabilities():
    try:
        # Connect to Tenable.sc
        sc = pyvas.connect('<Tenable.sc IP>', '<username>', '<password>')

        # Get the list of vulnerabilities
        vulnerabilities = sc.analysis.vulnerabilities()

        # Print the list of vulnerabilities
        for vuln in vulnerabilities:
            print(f"Tenable.sc Vulnerability: {vuln}")
    except Exception as e:
        logging.error(f"Error retrieving vulnerabilities from Tenable.sc: {e}")

def check_security():
    print("Security Assessment Report:")
    print("=" * 30)
    for vulnerability, info, mitigation in vulnerabilities:
        print("\n", "-" * 50)
        print(f"{vulnerability}: {info}")
        try:
            if "Windows Defender" in vulnerability and not is_defender_running():
                print(f"   - Vulnerability detected. {mitigation}")
            elif "Firewall" in vulnerability and not is_firewall_enabled():
                print(f"   - Vulnerability detected. {mitigation}")
            # Add more vulnerability checks here...
            else:
                print("   - No vulnerability detected.")
        except Exception as e:
            logging.error(f"Error checking {vulnerability}: {e}")

if __name__ == "__main__":
    check_vulnerabilities()
    check_security()
