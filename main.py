from extractor import extract_iocs
from reputation import check_ip, check_hash, check_domain, calculate_severity
from report import generate_report
from menu import show_menu
from viewer import read_report
import os


def analyze_log():
    print("\nAvailable log files:")

    files = os.listdir("alerts")

    for i, file in enumerate(files, start=1):
        print(f"{i}. {file}")

    print(f"{len(files) + 1}. Enter custom file path")

    choice = input("\nChoose: ")

    if choice.isdigit():
        choice = int(choice)

        if 1 <= choice <= len(files):
            file_name = os.path.join("alerts", files[choice - 1])

        elif choice == len(files) + 1:
            file_name = input("Enter full file path: ")

        else:
            print("Invalid choice.")
            return
    else:
        print("Invalid input.")
        return

    iocs = extract_iocs(file_name)

    alert_id = iocs["alert_id"]

    ip_stats = None
    hash_stats = None
    domain_stats = None

    if iocs["ips"]:
        ip_stats = check_ip(iocs["ips"][0])

    if iocs["md5"]:
        hash_stats = check_hash(iocs["md5"][0])

    if iocs["domains"]:
        domain_stats = check_domain(iocs["domains"][0])

    severity = calculate_severity(ip_stats)

    reputation = {
        "ip": ip_stats,
        "hash": hash_stats,
        "domain": domain_stats
    }

    generate_report(
        alert_id,
        iocs,
        reputation,
        severity
    )

    print("Report Generated Successfully")


while True:
    choice = show_menu()

    if choice == "1":
        analyze_log()

    elif choice == "2":
        read_report()

    elif choice == "3":
        print("Goodbye!")
        break

    else:
        print("Invalid choice!")