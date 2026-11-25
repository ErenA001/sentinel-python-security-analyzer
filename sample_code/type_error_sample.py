def calculate_total(items: list[int]) -> int:
    return sum(items)


# Deliberate type mismatch for the optional mypy demonstration.
total = calculate_total(["3", 4])
print(total)
