import json
import re


def clean_json_response(response_text):
    """
    Remove markdown formatting from LLM response.
    """

    # Remove ```json
    response_text = re.sub(r"```json", "", response_text)

    # Remove ```
    response_text = re.sub(r"```", "", response_text)

    return response_text.strip()


def validate_json(response_text):
    """
    Validate JSON response from LLM.
    """

    try:

        cleaned_response = clean_json_response(response_text)

        data = json.loads(cleaned_response)

        return True, data

    except Exception as e:

        return False, str(e)