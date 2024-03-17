import subprocess
import psutil
import logging
import pyvas
from tqdm import tqdm
from vuln_info import vulnerabilities

logging.basicConfig(filename='security_assessment.log', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def is_defender_running():
    try:
        return any("MsMpEng.exe" in proc.name() for proc in psutil.process_iter())
    except Exception as e:
        logging.error(f"Error checking Windows Defender: {e}")
        return False

def is_firewall_enabled():
    try:
        output = subprocess.run(["ufw", "status"], capture_output=True, text=True, check=True)
        return "Status: active" in output.stdout
    except Exception as e:
        logging.error(f"Error checking firewall status: {e}")
        return False

def check_vulnerabilities():
    try:
        sc = pyvas.connect('<Tenable.sc IP>', '<username>', '<password>')
        vulnerabilities_list = sc.analysis.vulnerabilities()

        with tqdm(total=len(vulnerabilities_list), desc='Scanning for vulnerabilities', unit='vulnerability') as pbar:
            for vuln in vulnerabilities_list:
                pbar.update(1)
                if vuln in vulnerabilities:
                    print(f"- {vuln[0]}: {vuln[1]}")
    except Exception as e:
        logging.error(f"Error retrieving vulnerabilities from Tenable.sc: {e}")

def check_security():
    print("Security Assessment Report:")
    print("=" * 30)
    security_issues = []
    for vulnerability, info, mitigation in vulnerabilities:
        try:
            if "Windows Defender" in vulnerability and not is_defender_running():
                security_issues.append(f"Vulnerability detected: {vulnerability}. {mitigation}")
            elif "Firewall" in vulnerability and not is_firewall_enabled():
                security_issues.append(f"Vulnerability detected: {vulnerability}. {mitigation}")
        except Exception as e:
            logging.error(f"Error checking {vulnerability}: {e}")

    if security_issues:
        print("\n".join(security_issues))
    else:
        print("No vulnerabilities detected.")

if __name__ == "__main__":
    check_vulnerabilities()
    check_security()
