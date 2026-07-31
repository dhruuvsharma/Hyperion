# Hyperion handbook build

The authored source is `docs/engineering/hyperion-llm-coordinator-handbook.md`. The builder creates
the six native PNG diagrams and the Word deliverable; LibreOffice or Microsoft Word can then export
the DOCX to PDF.

```powershell
python -m venv tmp/docs-venv
tmp/docs-venv/Scripts/python -m pip install -r tools/docs/requirements.txt
tmp/docs-venv/Scripts/python tools/docs/build_hyperion_handbook.py
```

Keep renderer output under `tmp/`. Before replacing a published handbook, rerun heading, table,
image, section, field, and accessibility audits and visually inspect every rendered page. The source
and generated DOCX/PDF are committed together so reviewers can compare the human-readable content
with the shared artifacts.
