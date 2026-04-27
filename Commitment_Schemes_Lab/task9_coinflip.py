import random
from task3_commitment_utils import commit_hash_randomized, verify_hash_randomized

print("=== Commitment-Based Fair Coin Flipping Protocol ===\n")
print(f"{'Trial':<7} {'Alice':>6} {'Bob':>5} {'Coin':>5} {'Verify':>8}")
print("-" * 40)

for trial in range(1, 21):
    # Step 1: Alice commits to her bit
    a = str(random.randint(0, 1))
    C, opening = commit_hash_randomized(a)

    # Step 2: Bob chooses his bit (after commitment is sent)
    b = random.randint(0, 1)

    # Step 3: Alice reveals; Bob verifies and computes coin
    ok = verify_hash_randomized(C, opening)
    if ok:
        c = int(opening["message"]) ^ b
        print(f"{trial:<7} {a:>6} {b:>5} {c:>5} {'OK':>8}")
    else:
        print(f"{trial:<7} {'?':>6} {b:>5} {'-':>5} {'FAIL':>8}")
