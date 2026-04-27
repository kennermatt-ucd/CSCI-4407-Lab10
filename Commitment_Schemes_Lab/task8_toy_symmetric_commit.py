import secrets


def xor_key_stream(key: bytes, length: int) -> bytes:
    stream = b""
    while len(stream) < length:
        stream += key
    return stream[:length]


def toy_encrypt(key: bytes, message: str) -> bytes:
    msg_bytes = message.encode()
    stream = xor_key_stream(key, len(msg_bytes))
    return bytes(a ^ b for a, b in zip(msg_bytes, stream))


def toy_decrypt(key: bytes, ciphertext: bytes) -> str:
    stream = xor_key_stream(key, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream)).decode()


def commit_symmetric(message: str):
    key = secrets.token_bytes(16)
    ciphertext = toy_encrypt(key, message)
    return ciphertext, {"message": message, "key_hex": key.hex()}


def verify_symmetric(commitment: bytes, opening: dict) -> bool:
    key = bytes.fromhex(opening["key_hex"])
    decrypted = toy_decrypt(key, commitment)
    return decrypted == opening["message"]


if __name__ == "__main__":
    print("=== Toy Symmetric Commitment Scheme ===\n")

    for message in ["42", "heads", "17", "secret"]:
        c, opening = commit_symmetric(message)
        ok = verify_symmetric(c, opening)
        print(f"Message:           {message!r}")
        print(f"Ciphertext (hex):  {c.hex()}")
        print(f"Key (hex):         {opening['key_hex']}")
        print(f"Verify:            {ok}")
        print("-" * 50)
