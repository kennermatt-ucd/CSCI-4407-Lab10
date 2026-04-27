import hashlib
import secrets


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def commit_hash_deterministic(message: str):
    """
    Weak scheme: c = H(m), opening is just m.
    Not hiding over small message spaces.
    """
    c = sha256_bytes(message.encode())
    return c, {"message": message}


def verify_hash_deterministic(c: str, opening: dict) -> bool:
    message = opening["message"]
    return sha256_bytes(message.encode()) == c


def commit_hash_randomized(message: str):
    """
    Stronger scheme: r <- {0,1}^128, c = H(r || m), opening is (r, m).
    Randomness hides the message even in small domains.
    """
    r = secrets.token_bytes(16)
    c = sha256_bytes(r + message.encode())
    return c, {"message": message, "randomness_hex": r.hex()}


def verify_hash_randomized(c: str, opening: dict) -> bool:
    message = opening["message"]
    r = bytes.fromhex(opening["randomness_hex"])
    return sha256_bytes(r + message.encode()) == c


if __name__ == "__main__":
    m = "42"

    c1, o1 = commit_hash_deterministic(m)
    print("Weak commitment:      ", c1)
    print("Weak verify:          ", verify_hash_deterministic(c1, o1))

    c2, o2 = commit_hash_randomized(m)
    print("Randomized commitment:", c2)
    print("Randomized verify:    ", verify_hash_randomized(c2, o2))
