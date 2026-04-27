import random
import hashlib
from task3_commitment_utils import commit_hash_deterministic, commit_hash_randomized

m0 = "17"
m1 = "42"


def attacker_deterministic(c):
    if hashlib.sha256(m0.encode()).hexdigest() == c:
        return 0
    return 1


def attacker_randomized(c):
    return random.randint(0, 1)


def run_trials(commit_func, attacker, trials=100):
    wins = 0
    for _ in range(trials):
        b = random.randint(0, 1)
        m = m0 if b == 0 else m1
        c, _ = commit_func(m)
        guess = attacker(c)
        if guess == b:
            wins += 1
    return wins / trials


det_acc = run_trials(commit_hash_deterministic, attacker_deterministic)
rand_acc = run_trials(commit_hash_randomized, attacker_randomized)

print("=== Hiding Experiment: Adversary Guessing Accuracy ===\n")
print(f"Deterministic scheme accuracy: {det_acc:.0%}  (expect ~100%)")
print(f"Randomized scheme accuracy:    {rand_acc:.0%}  (expect ~50%)")
