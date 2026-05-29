import json
import re


def extract_json(text: str) -> str:
    """
    Fully robust cleaner for LLM outputs.
    Removes all markdown noise.
    """

    if not text:
        return ""

    text = text.strip()

    # Remove ALL backtick blocks in any form
    text = re.sub(r"```json", "", text, flags=re.IGNORECASE)
    text = re.sub(r"```", "", text)

    return text.strip()


def force_extract_json_object(text: str):
    """
    Extract first valid JSON object from messy text.
    """

    try:
        start = text.find("{")
        end = text.rfind("}")

        if start != -1 and end != -1:
            return text[start:end+1]

    except:
        pass

    return text


def validate_json(response_text: str):

    try:
        cleaned = extract_json(response_text)
        cleaned = force_extract_json_object(cleaned)

        parsed = json.loads(cleaned)

        # IMPORTANT: always return dict on success
        return True, parsed

    except Exception as e:

        return False, {
            "error": "JSON_PARSE_ERROR",
            "message": str(e),
            "raw": response_text
        }