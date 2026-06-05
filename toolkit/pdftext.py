#!/usr/bin/env python3
"""pdftext.py - dump text from a PDF (e.g. audit reports) for the known-issues
baseline. Needs `pip install pypdf`. ASCII-safe output for Windows consoles.

    python toolkit/pdftext.py <file.pdf> [first_page] [last_page]

No args beyond the file = whole document. Pages are 1-indexed inclusive.
"""
import sys


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    from pypdf import PdfReader
    reader = PdfReader(sys.argv[1])
    n = len(reader.pages)
    a = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    b = int(sys.argv[3]) if len(sys.argv) > 3 else n
    a, b = max(1, a), min(b, n)
    print(f"[{n} pages total; showing {a}-{b}]")
    for i in range(a - 1, b):
        txt = reader.pages[i].extract_text() or ""
        # keep it ASCII for Windows consoles
        txt = txt.encode("ascii", "replace").decode("ascii")
        print(f"\n----- p{i + 1} -----\n{txt}")


if __name__ == "__main__":
    main()
