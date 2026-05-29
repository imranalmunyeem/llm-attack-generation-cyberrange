import json


def validate_json(response_text):
    """
    Validate JSON response from LLM.
    """

    try:
        data = json.loads(response_text)
        return True, data

    except Exception as e:
        return False, str(e)