import json

def generate_report(alert_id, iocs, reputation, severity):

    report = {

        "alert_id": alert_id,

        "iocs": iocs,

        "reputation": reputation,

        "severity": severity

    }

    with open("reports/report.json", "w") as file:
        iocs.pop("alert_id", None)
        json.dump(report, file, indent=4)