import hashlib
from task3_commitment_utils import commit_hash_deterministic

print("=== Weak Hash Commitment Brute-Force Attack ===\n")

secrets_to_test = ["77", "17", "42", "99", "1"]

for secret_message in secrets_to_test:
    c, opening = commit_hash_deterministic(secret_message)
    print(f"Secret:              {secret_message}")
    print(f"Observed commitment: {c}")

    recovered = None
    for i in range(1, 101):
        guess = str(i)
        if hashlib.sha256(guess.encode()).hexdigest() == c:
            recovered = guess
            break

    print(f"Recovered message:   {recovered}")
    print(f"Attack succeeded:    {recovered == secret_message}")
    print("-" * 60)
