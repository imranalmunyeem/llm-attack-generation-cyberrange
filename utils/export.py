import json
import pandas as pd


def export_json(data, output_file):
    with open(output_file, "w") as file:
        json.dump(data, file, indent=4)


def export_csv(data, output_file):
    df = pd.DataFrame(data)
    df.to_csv(output_file, index=False)