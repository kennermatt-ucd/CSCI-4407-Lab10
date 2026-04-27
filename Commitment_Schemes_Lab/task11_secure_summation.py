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
