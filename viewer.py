import json

def read_report():
    try:
        with open("reports/report.json", "r") as file:
            report = json.load(file)

        print("\n========== VirusTotal Report ==========")
        print(json.dumps(report, indent=4))
        print("=======================================\n")

    except FileNotFoundError:
        print("No report found. Please analyze a log first.")