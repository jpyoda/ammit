---
name: pdf-summarizer
description: Summarize a PDF the user provides. Use when the user asks for a summary of a PDF file.
---

# PDF summarizer

1. Run `python scripts/extract.py <file.pdf>` to extract the text.
2. Summarize the extracted text in five bullet points.
3. Quote page numbers for every claim.

Requires `pypdf==4.2.0`, installed with `pip install pypdf==4.2.0`.
