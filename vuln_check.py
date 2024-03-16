import subprocess
import winreg
import psutil
from vuln_info import vulnerabilities

def is_defender_running():
    return any("MsMpEng.exe" in proc.name() for proc in psutil.process_iter())

def is_firewall_enabled():
    output = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True, text=True)
    return "Firewall state: On" in output.stdout

def is_uac_enabled():
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
    value, _ = winreg.QueryValueEx(key, "EnableLUA")
    return value == 1

def is_rdp_enabled():
    output = subprocess.run(["reg", "query", "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"], capture_output=True, text=True)
    return "fDenyTSConnections    REG_DWORD    0x0" in output.stdout

def is_secureboot_enabled():
    output = subprocess.run(["bcdedit"], capture_output=True, text=True)
    return "Secure Boot State                 On" in output.stdout

def is_bitlocker_enabled():
    output = subprocess.run(["manage-bde", "-status"], capture_output=True, text=True)
    return "Fully Encrypted" in output.stdout

def check_security():
    print("Security Assessment Report:")
    print("=" * 30)
    for vulnerability, info, mitigation in vulnerabilities:
        print("\n", "-" * 50)
        print(f"{vulnerability}: {info}")
        if "Windows Defender" in vulnerability and not is_defender_running():
            print(f"   - Vulnerability detected. {mitigation}")
        elif "Windows Firewall" in vulnerability and not is_firewall_enabled():
            print(f"   - Vulnerability detected. {mitigation}")
        elif "User Account Control (UAC)" in vulnerability and not is_uac_enabled():
            print(f"   - Vulnerability detected. {mitigation}")
        elif "Remote Desktop Protocol (RDP)" in vulnerability and not is_rdp_enabled():
            print(f"   - Vulnerability detected. {mitigation}")
        elif "Secure Boot" in vulnerability and not is_secureboot_enabled():
            print(f"   - Vulnerability detected. {mitigation}")
        elif "BitLocker Drive Encryption" in vulnerability and not is_bitlocker_enabled():
            print(f"   - Vulnerability detected. {mitigation}")
        else:
            print("   - No vulnerability detected.")

check_security()
