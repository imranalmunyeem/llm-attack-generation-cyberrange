import json
import re


class DetectionRuleGenerator:

    def __init__(self):

        self.rules = {

            "T1566": {
                "sigma": "Suspicious Email Activity Detected",
                "splunk": "index=email OR attachment=*",
                "logic": "Phishing or malicious email behavior detected"
            },

            "T1078": {
                "sigma": "Suspicious Authentication Activity",
                "splunk": "index=auth EventCode=4625 OR success login from new IP",
                "logic": "Abnormal login or credential abuse detected"
            },

            "T1041": {
                "sigma": "Possible Data Exfiltration",
                "splunk": "bytes_out > bytes_in OR unusual outbound traffic",
                "logic": "Data leaving network unusually"
            },

            "T1486": {
                "sigma": "Ransomware Activity Detected",
                "splunk": "file_extension=.encrypted OR mass file changes",
                "logic": "Mass file encryption behavior"
            },

            "T1021": {
                "sigma": "Lateral Movement Detected",
                "splunk": "admin_share OR remote_exec OR ssh login spike",
                "logic": "Cross-system movement detected"
            },

            "T1203": {
                "sigma": "Exploit Execution Detected",
                "splunk": "process=*exploit* OR suspicious child process",
                "logic": "Exploit or payload execution detected"
            },

            "T1068": {
                "sigma": "Privilege Escalation Detected",
                "splunk": "sudo OR EventCode=4672 OR admin privilege grant",
                "logic": "Privilege escalation attempt detected"
            },

            "T1204": {
                "sigma": "Malicious User Execution",
                "splunk": "unknown process OR suspicious script execution",
                "logic": "User executed malicious or unknown file"
            }
        }

    def extract_techniques(self, text):

        pattern = r"T\d{4}(?:\.\d{3})?"
        return re.findall(pattern, text)

    def generate_rules(self, dataset):

        results = []

        for scenario in dataset:

            for stage in scenario.get("attack_stages", []):

                text = stage.get("stage_name", "") + " " + stage.get("description", "")

                techniques = self.extract_techniques(text)

                for tech in techniques:

                    if tech in self.rules:

                        rule = self.rules[tech]

                        results.append({
                            "technique": tech,
                            "sigma": rule["sigma"],
                            "splunk": rule["splunk"],
                            "logic": rule["logic"]
                        })

        return results


def load_dataset(path):

    data = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data.append(json.loads(line))

    return data


if __name__ == "__main__":

    dataset_path = "dataset/dataset.jsonl"

    dataset = load_dataset(dataset_path)

    generator = DetectionRuleGenerator()

    rules = generator.generate_rules(dataset)

    print("\nDETECTION RULES GENERATED:\n")

    for r in rules[:20]:
        print(r)

    print(f"\nTotal rules generated: {len(rules)}")