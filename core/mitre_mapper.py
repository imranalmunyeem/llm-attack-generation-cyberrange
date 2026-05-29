class MitreMapper:

    def __init__(self):

        # simple rule-based mapping (we will improve later with LLM)
        self.rules = {

            "phishing": "T1566",
            "email": "T1566",
            "credential": "T1078",
            "login": "T1078",
            "ransomware": "T1486",
            "malware": "T1204",
            "execution": "T1203",
            "privilege": "T1068",
            "lateral movement": "T1021",
            "exfiltration": "T1041"
        }

    def map_text_to_techniques(self, text):

        text = text.lower()

        matched = []

        for key, technique in self.rules.items():

            if key in text:
                matched.append(technique)

        return matched