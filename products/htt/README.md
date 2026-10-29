# Hyperion Terminal Transformer (HTT)

HTT is the proposed narrow model for Terminal strategy and visualizer authoring. This folder is the
canonical home for HTT research and, after protocol review, model-specific architecture and evaluation
artifacts.

## Current artifacts

- [Canonical LaTeX research paper](research/hyperion-terminal-transformer-research-paper.tex)
- [Academic preprint PDF](research/hyperion-terminal-transformer-research-paper.pdf)
- [PDF build tool](tools/build_research_paper.py)
- [Earlier narrative Markdown](research/hyperion-terminal-transformer-research-paper.md)

The canonical paper uses native LaTeX mathematics, TikZ vector figures, a notation table, and an
abbreviation glossary. Build it with Tectonic 0.17.0 on `PATH` (or set `TECTONIC` to that executable),
then run the PDF build tool from the repository root.

No HTT checkpoint or trained weights exist. The broader governed model-data, evaluation, promotion,
and serving harness remains under `tools/hyperion-model` because it serves the full Hyperion model
portfolio and carries established schema and compatibility paths.
