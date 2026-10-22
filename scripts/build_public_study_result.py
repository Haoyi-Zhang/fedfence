"""Retired legacy aggregator. It does not regenerate scientific results."""


def main():
    raise SystemExit(
        "Retired: results/public_change_study.json belongs to the historical route. "
        "Use tosem/results/public_study.csv/.json for the selected 21 configurations. "
        "The formal regeneration entrypoint is scripts/reproduce_tosem.py; "
        "it runs a full campaign. This retired helper writes nothing."
    )


if __name__ == "__main__":
    main()
