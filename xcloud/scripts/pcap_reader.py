"""
PCAP Parser for XCloud network traffic
"""
import argparse

def parse_file(filepath: str) -> None:
    print(f"hello -> {filepath}")

def main():
    parser = argparse.ArgumentParser(
        "XCloud PCAP parser",
        description="PCAP Parser for XCloud network traffic"
    )
    parser.add_argument("filepath", help="Path to PCAP/NG file")
    args = parser.parse_args()

    parse_file(args.filepath)

if __name__ == "__main__":
    main()
