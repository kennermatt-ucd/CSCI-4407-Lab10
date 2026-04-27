from task3_commitment_utils import commit_hash_randomized, verify_hash_randomized

m = "42"
results = []

for _ in range(5):
    c, opening = commit_hash_randomized(m)
    ok = verify_hash_randomized(c, opening)
    results.append((c, opening, ok))

for idx, item in enumerate(results):
    print(f"Trial {idx + 1}")
    print("Commitment:", item[0])
    print("Opening:   ", item[1])
    print("Verify:    ", item[2])
    print("-" * 60)
