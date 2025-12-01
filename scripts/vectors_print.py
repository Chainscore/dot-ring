#!/usr/bin/env python3
"""
Pretty print test vectors for human readability.

Usage:
    python vectors_print.py <vectors.json>
"""

import json
import sys

# Max lengths for the entries before splitting on multiple lines
ENTRIES_MAX_LENGTHS = {
    # Common stuff
    "sk": 64,
    "pk": 66,
    "alpha": 64,
    "ad": 64,
    "h": 66,
    "gamma": 66,
    "beta": 128,  # 64 bytes = 128 hex chars
    "salt": 64,
    # IETF proof entries
    "proof_c": 64,
    "proof_s": 64,
    # Pedersen extra entries
    "blinding": 64,
    "proof_pk_com": 66,
    "proof_r": 66,
    "proof_ok": 66,
    "proof_sb": 64,
    # Ring extra entries
    "ring_pks": 66,  # Will wrap
    "ring_pks_com": 66,
    "ring_proof": 66,
    "prover_idx": 10,
}


def print_entry(
    entry: dict, key: str, max_length: int = 64, continuation_prefix: str = ".."
) -> None:
    """Print a single entry, wrapping long values."""
    value = entry.get(key, "-")
    if value is None:
        value = "-"
    elif isinstance(value, int):
        value = str(value)

    text = value if value else "-"
    label = f"{key}: "

    # Print label on first line
    if len(text) <= max_length - len(label):
        print(f"{label}{text}")
        return

    # Multi-line output
    print(f"{label}")
    while len(text) > max_length:
        split_point = max_length
        print(f"  {text[:split_point]}")
        text = text[split_point:]
    if text:
        print(f"  {text}")


def main(file_name: str) -> None:
    """Main function to process and print vectors."""
    with open(file_name) as file:
        data = json.load(file)

    if not data:
        print("Empty vector file")
        return

    # Determine schema from first entry
    print("----- SCHEMA -----")
    schema = []
    for key in data[0]:
        if key == "comment":
            continue
        length = ENTRIES_MAX_LENGTHS.get(key, 64)
        schema.append((key, length))
        print(key)
    print("------------------\n")

    # Print each vector
    for entry in data:
        comment = entry.get("comment", "???")
        print(f"### {comment}")
        print()
        print("```")
        for key, line_max in schema:
            print_entry(entry, key, line_max)
        print("```")
        print()


def compare_vectors(file1: str, file2: str) -> None:
    """Compare two vector files for differences."""
    with open(file1) as f:
        data1 = json.load(f)
    with open(file2) as f:
        data2 = json.load(f)

    print(f"Comparing {file1} vs {file2}")
    print(f"File 1: {len(data1)} vectors")
    print(f"File 2: {len(data2)} vectors")
    print()

    # Compare each vector
    for i, (v1, v2) in enumerate(zip(data1, data2, strict=False)):
        diffs = []
        for key in set(v1.keys()) | set(v2.keys()):
            val1 = v1.get(key)
            val2 = v2.get(key)
            if val1 != val2:
                diffs.append(
                    f"  {key}: {val1[:20] if val1 else '-'}... != {val2[:20] if val2 else '-'}..."
                )

        if diffs:
            print(f"Vector {i + 1}: DIFFERS")
            for d in diffs:
                print(d)
        else:
            print(f"Vector {i + 1}: OK")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <vectors.json>")
        print(f"       {sys.argv[0]} --compare <file1.json> <file2.json>")
        sys.exit(1)

    if sys.argv[1] == "--compare" and len(sys.argv) == 4:
        compare_vectors(sys.argv[2], sys.argv[3])
    else:
        main(sys.argv[1])
