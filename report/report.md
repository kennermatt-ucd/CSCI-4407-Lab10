# Department of Computer Science & Engineering
## CSCI/CSCY 4407: Security & Cryptography
## Lab 10 Report: Commitment Schemes, Fair Protocols, and Secure Summation

**Group Number:** Group 10  
**Semester:** Spring 2026  
**Instructor:** Dr. Victor Kebande  
**Teaching Assistant:** Celest Kester  
**Submission Date:** May 1, 2026

**Group Members:**
- Matthew Kenner
- Jonathan Le
- Cassius Kemp

---

## Table of Contents

1. [Introduction](#introduction)
2. [Environment](#environment)
3. [Files Included](#files-included)
4. [Task 1 – Directory and File Setup](#task-1)
5. [Task 2 – Unfair Casino Protocol Analysis](#task-2)
6. [Task 3 – Commitment Interface (Python)](#task-3)
7. [Task 4 – Weak Hash Commitment Attack](#task-4)
8. [Task 5 – Randomized Hash Commitment](#task-5)
9. [Task 6 – Hiding Experiment](#task-6)
10. [Task 7 – Binding Analysis](#task-7)
11. [Task 8 – Encryption-Based Commitments](#task-8)
12. [Task 9 – Coin Flipping Protocol](#task-9)
13. [Task 10 – Protocol Security Analysis](#task-10)
14. [Task 11 – Secure Summation](#task-11)
15. [Task 12 – Comparison and Reflection](#task-12)
16. [Appendix – Scripts](#appendix)

---

## Introduction

This report documents the implementation and analysis of cryptographic commitment schemes and their applications in fair protocol design. The lab explores hiding and binding properties, demonstrates weaknesses in deterministic constructions, introduces randomized commitments, and applies these concepts to coin-flipping and secure summation protocols.

---

## Environment

- **Operating System:** Kali Linux / Ubuntu
- **Python Version:** Python 3.x
- **Libraries Used:** hashlib, secrets, random
- **Terminal:** Linux terminal

---

## Files Included

- `task3_commitment_utils.py`
- `task4_weak_hash_attack.py`
- `task5_randomized_hash_experiment.py`
- `task6_hiding_experiment.py`
- `task8_toy_symmetric_commit.py`
- `task9_coinflip.py`
- `task11_secure_summation.py`

---

## Task 1 – Directory and File Setup

### Objective
Set up working environment and baseline files.

### Commands / Code Used

```bash
mkdir Commitment_Schemes_Lab
cd Commitment_Schemes_Lab

echo "42" > guess_player.txt
echo "77" > casino_secret.txt
echo "1"  > coin_input_a.txt
echo "0"  > coin_input_b.txt

cat guess_player.txt
cat casino_secret.txt
cat coin_input_a.txt
cat coin_input_b.txt

pwd
ls -l

sha256sum guess_player.txt casino_secret.txt coin_input_a.txt coin_input_b.txt
```

### Output Evidence

![alt text](image-1.png)

![alt text](image-2.png)

### Explanation

Having concrete fixed values before the commitment experiments makes the results easier to interpret. When a message is pinned to a specific number like `42` or `77`, the experiment traces a deterministic path: the commitment we compute, the brute-force guess we recover, and the XOR result we produce are all traceable back to a known starting point. Without fixed inputs, every run produces different values and it becomes impossible to verify correctness by inspection.

More broadly, fixing values during protocol reasoning is a standard technique in security analysis. It lets us confirm that our implementation is correct before we add randomness, and it clarifies the attacker's information advantage. Once we can confirm correct behavior on fixed inputs, we can add the randomness required for real security.

---

## Task 2 – Unfair Casino Protocol Analysis

![alt text](image.png)

### Why the Protocol Fails

The failure is not weak randomness — the casino's T may still be drawn "randomly" from the remaining 99 values. The failure is **information asymmetry induced by message ordering**. Fairness requires T ⊥ G, i.e. P(T = t | G = g) = P(T = t) = 1/100 for all g, t. The naive protocol violates this: because G is revealed before T is chosen, the casino can condition on G, producing a distribution where (See screenshot)
T and G are therefore not independent, and no prize structure can restore the player's expected value. Any protocol where one party reveals a committed value before the other party chooses breaks this independence requirement.

---

## Task 3 – Commitment Interface (Python)

### Objective

Implement both a weak (deterministic) and a stronger (randomized) hash-based commitment scheme in a reusable Python module.

### Code

```python
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
```

### Output Evidence

![alt text](image-3.png)

### Explanation

Both commitment variants pass verification, which confirms functional correctness: a receiver who is given the opening information can always recompute the commitment and confirm it matches. However, functional correctness is not the same as security.

The deterministic scheme `C = H(m)` verifies correctly because SHA-256 is a deterministic function: the same input always produces the same output. But this property also means an adversary who knows the message space can precompute the hash for every candidate and compare. When the message space is small, as in a 1-to-100 casino guess, the scheme gives away the committed value entirely.

The randomized scheme `C = H(r || m)` also verifies correctly because the opening includes the randomness `r`. Given `(r, m)`, the verifier recomputes `H(r || m)` and matches it to `C`. But because `r` is 128 bits of fresh randomness chosen at commit time, an adversary who only sees `C` cannot recover `m` by exhaustive search—the search space is now 2^128, not 100.

---

## Task 4 – Weak Hash Commitment Attack

### Objective

Demonstrate that the deterministic hash commitment fails the hiding property when the message space is small.

### Code

```python
import hashlib
from commitment_utils import commit_hash_deterministic

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
```

### Output Evidence

![alt text](image-4.png)

### Explanation

The scheme fails hiding because SHA-256 is a deterministic, public function. An adversary who knows the message space can compute `H(i)` for every candidate `i` in `{1, ..., 100}` and compare each result to the observed commitment. Since there are only 100 candidates, this loop completes almost instantly and always succeeds.

This attack is feasible precisely because the domain is small. In a real message space of arbitrary strings, the same exhaustive approach would require evaluating an astronomically large number of possibilities. The weakness is not in SHA-256 itself but in the mismatch between the function's determinism and the small input domain.

This directly mirrors the unfair casino scenario from the slides. The casino acts as the attacker: it receives the player's commitment `H(G)` and immediately recovers `G` by looping from 1 to 100. Having recovered the player's guess, it can always pick `T ≠ G` and ensure the player never wins.

---

## Task 5 – Randomized Hash Commitment

### Objective

Show that committing to the same message multiple times under the randomized scheme produces different commitments, while each still verifies correctly.

### Code

```python
from commitment_utils import commit_hash_randomized, verify_hash_randomized

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
```

### Output Evidence

```
Trial 1
Commitment: 25df694b2376b92546ded5c7f8b252902372a56c1dce92ac31a87de40a3d23fd
Opening:    {'message': '42', 'randomness_hex': '956cc8e38ce157c33dbd2b3e4e8708b3'}
Verify:     True
------------------------------------------------------------
Trial 2
Commitment: 7b00539d6d9a21a0349bee9338b75d68eec23c2daf81c0064655a47c02081929
Opening:    {'message': '42', 'randomness_hex': 'db3193fd27b40188426b9401d7fe6cd8'}
Verify:     True
------------------------------------------------------------
Trial 3
Commitment: 53388fc267187885268e218a3fc2d0cc6686ccc3b8367eaa5cddfa037fb1462c
Opening:    {'message': '42', 'randomness_hex': '5c70660f4fe17b0320154265980af73a'}
Verify:     True
------------------------------------------------------------
Trial 4
Commitment: 5d9522460042aff43f8f2041610225ff9dccd64a0a8ca840a6fcdc37c888ea5a
Opening:    {'message': '42', 'randomness_hex': 'ea7570e12e4424af1c3b5bb4c5d113f2'}
Verify:     True
------------------------------------------------------------
Trial 5
Commitment: 31136a863b8a124118d69931224ead753d24d5689e619e9612a1057fc8d83592
Opening:    {'message': '42', 'randomness_hex': '4568827498aa53fe9bf009660ada0c77'}
Verify:     True
------------------------------------------------------------
```

> [SCREENSHOT – terminal running randomized_hash_experiment.py showing 5 distinct commitments for the same message "42"]

### Explanation

Every trial commits to the same message `"42"` but produces a completely different commitment string because each call to `commit_hash_randomized` draws a fresh 128-bit random nonce `r` from `secrets.token_bytes(16)`. The commitment is computed as `H(r || m)`, so even though `m` is constant, the input to SHA-256 differs each time, producing an unrelated output.

This randomness is what hides the message. An adversary who only sees `C = H(r || m)` cannot recover `m` by exhaustive search because they also need to guess `r`, which has 2^128 possible values. Unlike the deterministic scheme, a precomputed lookup table over `{1, ..., 100}` is useless here.

Verification still works because the opening information includes both `m` and `r`. The verifier recomputes `H(r || m)` and checks it against `C`. The randomness does not weaken verification; it just ensures that the commitment itself carries no information about `m` to anyone who lacks `r`.

---

## Task 6 – Hiding Experiment

### Objective

Empirically measure how hiding changes when the scheme is deterministic versus randomized, using a guessing adversary over 100 trials.

### Code

```python
import random
import hashlib
from commitment_utils import commit_hash_deterministic, commit_hash_randomized

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
```

### Output Evidence

```
=== Hiding Experiment: Adversary Guessing Accuracy ===

Deterministic scheme accuracy: 100%  (expect ~100%)
Randomized scheme accuracy:    54%   (expect ~50%)
```

> [SCREENSHOT – terminal running hiding_experiment.py]

### Results Table

| Scheme        | Accuracy |
| ------------- | -------- |
| Deterministic | ~100%    |
| Randomized    | ~50%     |

### Explanation

The deterministic attacker achieves 100% accuracy because `H(m)` is a fixed, publicly reproducible function. Given the commitment `C`, the attacker simply computes `H("17")` and `H("42")` and checks which one matches. This is an exact dictionary lookup and requires no guessing. The scheme is completely distinguishable in a two-message domain.

The randomized attacker achieves approximately 50% accuracy, which is no better than random guessing. Because the commitment is `H(r || m)` with a fresh random `r`, no information about whether `m0` or `m1` was committed is leaked through the commitment value alone. The attacker has no way to distinguish the two cases and is reduced to flipping a coin.

This result directly illustrates the formal hiding game from the lecture. A scheme is hiding if no efficient adversary can distinguish a commitment to `m0` from a commitment to `m1` with probability significantly better than 1/2. The randomized scheme passes this test empirically; the deterministic scheme fails it completely.

---

## Task 7 – Binding Analysis

### Objective

Explain binding property.

### Evidence

> [HANDWRITTEN]

### Explanation

* Binding = cannot open two ways
* Requires collision resistance
* Not proven by experiments

---

## Task 8 – Encryption-Based Commitments

### Objective

Implement a toy symmetric encryption-based commitment and explain the public-key construction conceptually.

### Code

```python
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
```

### Output Evidence

```
=== Toy Symmetric Commitment Scheme ===

Message:           '42'
Ciphertext (hex):  7607
Key (hex):         423542dc7eed239d7e3445f90ce636b5
Verify:            True
--------------------------------------------------
Message:           'heads'
Ciphertext (hex):  be3d033c12
Key (hex):         d658625861e180e199b7c2fa17e14cce
Verify:            True
--------------------------------------------------
Message:           '17'
Ciphertext (hex):  ad63
Key (hex):         9c54cd2ff556ed828fb041fa396f8580
Verify:            True
--------------------------------------------------
Message:           'secret'
Ciphertext (hex):  f9932fccb35a
Key (hex):         8af64cbed62ea406dc7b53cd4cce12c2
Verify:            True
--------------------------------------------------
```

> [SCREENSHOT – terminal running toy_symmetric_commit.py]

### Explanation

**Part A – Symmetric XOR Construction**

The commitment is `C = Enc_K(M)` where `K` is a freshly generated 128-bit key and `Enc` is a repeating XOR keystream cipher. The opening information is `(M, K)`. Verification decrypts the ciphertext with `K` and checks that the result equals `M`.

Hiding appears plausible here because anyone who sees only `C` without knowing `K` cannot recover `M`—the XOR keystream looks random relative to the message. However, this toy experiment is not itself a proof of commitment security. A real proof would require showing that the encryption scheme is semantically secure, and XOR with a repeating key is not semantically secure for messages longer than the key.

Binding is more subtle. The commitment `C = Enc_K(M)` is binding relative to the key `K`: there is only one decryption of `C` under a fixed `K`, so a committer cannot open `C` to two different messages using the same `K`. However, a committer who is allowed to choose a different key at opening time could potentially produce a collision, which would break binding. This is why real commitment schemes either tie the key to the commitment itself or use a hash to enforce uniqueness.

**Part B – Public-Key Construction (Conceptual)**

In a public-key based commitment, a key pair `(pk, sk)` is generated and `pk` is published. The committer computes:

```
C = E_pk(M; R)
```

where `R` is fresh randomness used in the encryption. The opening is `(M, R)`. Verification re-encrypts `M` with `R` under `pk` and checks that the result matches `C`.

Hiding holds because the encryption is semantically secure under the public key—seeing `C` reveals nothing about `M` to an adversary without `sk`. Binding holds because any valid opening of `C` is a pair `(M, R)` such that `E_pk(M; R) = C`. If the encryption scheme has unique decryption under `sk`, then `C` can decrypt to at most one `M`, making it computationally infeasible to find two different openings. This construction is stronger than the hash-based scheme in that binding is tied to a computational assumption about the asymmetric cipher rather than collision resistance of a hash.

---

## Task 9 – Coin Flipping Protocol

### Objective

Implement a fair two-party coin-flipping protocol using the randomized hash commitment.

### Code

```python
import random
from commitment_utils import commit_hash_randomized, verify_hash_randomized

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
```

### Output Evidence

```
=== Commitment-Based Fair Coin Flipping Protocol ===

Trial    Alice   Bob  Coin   Verify
----------------------------------------
1            1     0     1       OK
2            1     0     1       OK
3            1     0     1       OK
4            0     1     1       OK
5            1     1     0       OK
6            1     1     0       OK
7            0     1     1       OK
8            1     0     1       OK
9            0     1     1       OK
10           0     1     1       OK
11           1     0     1       OK
12           1     1     0       OK
13           1     1     0       OK
14           1     0     1       OK
15           1     0     1       OK
16           1     1     0       OK
17           0     0     0       OK
18           0     0     0       OK
19           1     1     0       OK
20           0     1     1       OK
```

> [SCREENSHOT – terminal running coinflip.py showing 20 trials all verifying OK]

### Explanation

The commitment must be sent before Bob chooses `b`. This ordering is the key to fairness. If Alice committed after seeing `b`, she could choose `a` to force any coin value she wanted. By committing first, Alice locks her bit `a` into a cryptographic container before Bob's choice is known. The commitment scheme ensures she cannot change `a` after the fact (binding property), and Bob cannot determine `a` from the commitment before Alice reveals it (hiding property).

The final coin `c = a XOR b` is fair because neither party can control the output unilaterally. Alice fixes `a` before seeing `b`, so she cannot bias the XOR. Bob chooses `b` after the commitment is sent but before Alice reveals, so he is not adapting to `a` either. The XOR of two independently chosen bits is uniformly distributed over `{0, 1}`, giving each outcome equal probability. Verification ensures that Alice reveals the same `a` she originally committed to, and not a manipulated value.

---

## Task 10 – Protocol Security Analysis

### Objective

Analyze cheating.

### Evidence

> [HANDWRITTEN]

### Explanation

* Alice cheats → breaks binding
* Bob cheats → breaks hiding
* Both required for fairness

---

## Task 11 – Secure Summation

### Objective

Implement a three-party secure summation protocol using additive secret sharing modulo M = 3N.

### Code

```python
import random

N = 100
M = 3 * N

inputs = [17, 42, 23]


def share_value(x, num_parties=3, mod=M):
    shares = [random.randint(0, mod - 1) for _ in range(num_parties - 1)]
    final_share = (x - sum(shares)) % mod
    shares.append(final_share)
    return shares


print("=== Secure Summation Protocol (3 parties) ===\n")

for run in range(1, 4):
    matrix = [share_value(x) for x in inputs]
    column_sums = [sum(matrix[i][j] for i in range(3)) % M for j in range(3)]
    total = sum(column_sums) % M
    actual = sum(inputs) % M

    print(f"Run {run}:")
    print(f"  Inputs:          {inputs}")
    for i, row in enumerate(matrix):
        print(f"  Party {i+1} shares:  {row}")
    print(f"  Column sums:     {column_sums}")
    print(f"  Recovered total: {total}")
    print(f"  Actual total:    {actual}")
    print(f"  Match:           {total == actual}\n")
```

### Output Evidence

```
=== Secure Summation Protocol (3 parties) ===

Run 1:
  Inputs:          [17, 42, 23]
  Party 1 shares:  [114, 155, 48]
  Party 2 shares:  [207, 268, 167]
  Party 3 shares:  [192, 284, 147]
  Column sums:     [213, 107, 62]
  Recovered total: 82
  Actual total:    82
  Match:           True

Run 2:
  Inputs:          [17, 42, 23]
  Party 1 shares:  [57, 212, 48]
  Party 2 shares:  [211, 137, 294]
  Party 3 shares:  [2, 77, 244]
  Column sums:     [270, 126, 286]
  Recovered total: 82
  Actual total:    82
  Match:           True

Run 3:
  Inputs:          [17, 42, 23]
  Party 1 shares:  [242, 98, 277]
  Party 2 shares:  [110, 15, 217]
  Party 3 shares:  [209, 232, 182]
  Column sums:     [261, 45, 76]
  Recovered total: 82
  Actual total:    82
  Match:           True
```

> [SCREENSHOT – terminal running secure_summation.py showing 3 runs all matching]

### Explanation

Individual shares do not reveal a private input because each party's share is an independently chosen random value modulo M. Party 1's input of 17 might be split into shares `[114, 155, 48]`. Any one of those numbers is statistically independent of 17—it is drawn uniformly at random from `{0, ..., M-1}`. A party who receives only one share cannot distinguish whether the original input was 17 or any other value. Privacy holds as long as at least one share stays private.

The final sum is still recovered correctly because of the algebraic property of additive shares. Each party's shares sum to their input modulo M:

```
x_{i,1} + x_{i,2} + x_{i,3} ≡ x_i (mod M)
```

When we sum all three column sums, we are summing every share across every party, which equals the sum of all inputs modulo M:

```
C_1 + C_2 + C_3 ≡ x_1 + x_2 + x_3 (mod M)
```

This connects to the secure summation protocol from the slides, which shows that secret sharing allows parties to jointly compute a linear function of their inputs without revealing the inputs themselves. The sum is computable from public column aggregates while each individual input remains hidden.

---

## Task 12 – Comparison and Reflection

### Comparison Table

| Mechanism          | Hiding | Binding | Weakness                              |
| ------------------ | ------ | ------- | ------------------------------------- |
| Naive Casino       | No     | No      | Casino sees guess before choosing T   |
| Deterministic Hash | No     | Yes     | Brute-forceable in small domains      |
| Randomized Hash    | Yes    | Yes     | Security relies on collision resistance of hash |
| Coin Flip Protocol | Yes    | Yes     | Requires both properties; breaks if either fails |

---

### Reflection

**Why the naive casino protocol is unfair**

The protocol allows the casino to observe the player's guess G before choosing its own value T. Because the casino moves second with full knowledge of G, it can always pick T ≠ G. The protocol appears random on the surface, but the asymmetric information flow lets the casino eliminate the only winning outcome. The problem is not weak randomness—it is that the order of messages gives one party a decisive information advantage.

**Why commitment schemes repair that fairness problem**

A commitment scheme forces the first mover to lock in a value before the second party responds. In the repaired protocol, the player commits to G, the casino chooses T without seeing G, then the player reveals G. Because the commitment is binding, the player cannot change G after seeing T. Because the commitment is hiding, the casino cannot see G before choosing T. Both parties move under uncertainty, and neither can adapt to the other's choice.

**Why deterministic hashing fails hiding in small domains**

`H(m)` is a fixed, public, computable function. When the message space has only 100 elements, an adversary builds a lookup table of all 100 hash values and finds a match for any observed commitment in at most 100 steps. The hash function itself is not broken; the failure comes from a small domain making exhaustive search practical.

**Why adding randomness changes the security picture**

The scheme `H(r || m)` with a fresh 128-bit nonce `r` explodes the effective search space from 100 to 2^128. An adversary who sees the commitment cannot recover m by enumeration because they would need to guess r as well. Each commitment to the same message looks completely different, preventing dictionary-style attacks.

**Why hiding and binding are different and complementary**

Hiding protects the committed value from being learned before the reveal phase—it is a privacy guarantee directed at the receiver. Binding prevents the committer from opening the same commitment to a different value—it is an integrity guarantee directed at the committer. A scheme can fail one property while satisfying the other. For example, a scheme that returns the message in plaintext is perfectly binding but not hiding at all. Both properties are required simultaneously for commitment schemes to be useful in protocols.

**How coin flipping uses commitment to enforce fairness**

Alice commits to her bit `a` before Bob chooses `b`. The hiding property stops Bob from learning `a` and biasing his choice. The binding property stops Alice from changing `a` after seeing `b`. The output `c = a XOR b` is then a uniform bit that neither party controlled, because each party's input was locked before the other's was visible.

**How secure summation extends the same mindset toward secure multiparty computation**

Secure summation shows that cryptographic techniques can let multiple parties compute a joint function—here, a sum—without any party learning the individual inputs of the others. The additive share mechanism provides information-theoretic privacy for each input: any single share is statistically independent of the original value. This is a direct instance of secure multiparty computation, where the goal is to compute functions on private data without a trusted third party. Commitment schemes play a related role in larger MPC protocols by ensuring parties commit to inputs before the computation begins, preventing adaptive manipulation.

---

## Appendix – Scripts

### task3_commitment_utils.py

```python
import hashlib
import secrets


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def commit_hash_deterministic(message: str):
    c = sha256_bytes(message.encode())
    return c, {"message": message}


def verify_hash_deterministic(c: str, opening: dict) -> bool:
    message = opening["message"]
    return sha256_bytes(message.encode()) == c


def commit_hash_randomized(message: str):
    r = secrets.token_bytes(16)
    c = sha256_bytes(r + message.encode())
    return c, {"message": message, "randomness_hex": r.hex()}


def verify_hash_randomized(c: str, opening: dict) -> bool:
    message = opening["message"]
    r = bytes.fromhex(opening["randomness_hex"])
    return sha256_bytes(r + message.encode()) == c
```

### task4_weak_hash_attack.py

```python
import hashlib
from commitment_utils import commit_hash_deterministic

secrets_to_test = ["77", "17", "42", "99", "1"]

for secret_message in secrets_to_test:
    c, opening = commit_hash_deterministic(secret_message)
    recovered = None
    for i in range(1, 101):
        if hashlib.sha256(str(i).encode()).hexdigest() == c:
            recovered = str(i)
            break
    print(f"Secret: {secret_message}  Recovered: {recovered}  Match: {recovered == secret_message}")
```

### task5_randomized_hash_experiment.py

```python
from commitment_utils import commit_hash_randomized, verify_hash_randomized

m = "42"
for _ in range(5):
    c, opening = commit_hash_randomized(m)
    ok = verify_hash_randomized(c, opening)
    print("Commitment:", c, "| Verify:", ok)
```

### task6_hiding_experiment.py

```python
import random
import hashlib
from commitment_utils import commit_hash_deterministic, commit_hash_randomized

m0, m1 = "17", "42"

def attacker_deterministic(c):
    return 0 if hashlib.sha256(m0.encode()).hexdigest() == c else 1

def attacker_randomized(c):
    return random.randint(0, 1)

def run_trials(commit_func, attacker, trials=100):
    wins = sum(
        1 for _ in range(trials)
        if attacker(commit_func(m0 if (b := random.randint(0, 1)) == 0 else m1)[0]) == b
    )
    return wins / trials

print("Deterministic:", run_trials(commit_hash_deterministic, attacker_deterministic))
print("Randomized:   ", run_trials(commit_hash_randomized, attacker_randomized))
```

### task8_toy_symmetric_commit.py

```python
import secrets

def xor_key_stream(key, length):
    s = b""
    while len(s) < length:
        s += key
    return s[:length]

def toy_encrypt(key, message):
    mb = message.encode()
    return bytes(a ^ b for a, b in zip(mb, xor_key_stream(key, len(mb))))

def toy_decrypt(key, ciphertext):
    return bytes(a ^ b for a, b in zip(ciphertext, xor_key_stream(key, len(ciphertext)))).decode()

def commit_symmetric(message):
    key = secrets.token_bytes(16)
    return toy_encrypt(key, message), {"message": message, "key_hex": key.hex()}

def verify_symmetric(commitment, opening):
    return toy_decrypt(bytes.fromhex(opening["key_hex"]), commitment) == opening["message"]
```

### task9_coinflip.py

```python
import random
from commitment_utils import commit_hash_randomized, verify_hash_randomized

for trial in range(1, 21):
    a = str(random.randint(0, 1))
    C, opening = commit_hash_randomized(a)
    b = random.randint(0, 1)
    ok = verify_hash_randomized(C, opening)
    if ok:
        c = int(opening["message"]) ^ b
        print(f"Trial {trial:02d}: Alice={a}, Bob={b}, coin={c}, verify=OK")
```

### task11_secure_summation.py

```python
import random

N, M = 100, 300
inputs = [17, 42, 23]

def share_value(x, mod=M):
    shares = [random.randint(0, mod - 1) for _ in range(2)]
    shares.append((x - sum(shares)) % mod)
    return shares

matrix = [share_value(x) for x in inputs]
column_sums = [sum(matrix[i][j] for i in range(3)) % M for j in range(3)]
total = sum(column_sums) % M
print("Recovered total:", total, "| Actual:", sum(inputs) % M)
```

---

