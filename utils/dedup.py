import hashlib


def generate_hash(text):
    return hashlib.md5(text.encode()).hexdigest()


def is_duplicate(new_text, existing_hashes):

    new_hash = generate_hash(new_text)

    if new_hash in existing_hashes:
        return True

    existing_hashes.add(new_hash)

    return False