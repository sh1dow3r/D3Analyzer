import argparse
import sys
from disk_analyzer import DiskAnalyzer


def main():
    """Command-line interface for running the disk analysis."""
    parser = argparse.ArgumentParser(description="Forensic Disk Analysis using Fox-IT Dissect")
    parser.add_argument("targets", metavar="TARGETS", nargs="+", help="Disk images to analyze")

    args = parser.parse_args()  # ✅ FIXED: No `process_generic_arguments(args)`

    analyzer = DiskAnalyzer(args.targets)
    results = analyzer.run_analysis()

    # Print the analysis report
    for result in results:
        print("\n=== Disk Analysis Report ===")
        print(f"Hostname: {result['basic_info']['hostname']}")
        print(f"OS Version: {result['basic_info']['os_version']}")
        print(f"Users: {result['basic_info']['users']}")

        print("\n=== Partitions ===")
        for p in result["partitions"]:
            print(f"Offset: {p['offset']}, Size: {p['size']} bytes, Type: {p['type']}, FS: {p['filesystem']}")

        # print("\n=== Plugin Results ===")
        # for plugin, data in result["plugins"].items():
        #     print(f"\n[+] {plugin}:\n{data}")

        print("\n[+] Analysis completed successfully!\n")


if __name__ == "__main__":
    main()
