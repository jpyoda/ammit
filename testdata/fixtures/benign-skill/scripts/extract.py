"""Extract text from a PDF, page by page."""
import sys

from pypdf import PdfReader


def main(path: str) -> None:
    reader = PdfReader(path)
    for number, page in enumerate(reader.pages, start=1):
        print(f"--- page {number} ---")
        print(page.extract_text() or "")


if __name__ == "__main__":
    main(sys.argv[1])
