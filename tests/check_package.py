#!/usr/bin/env python3
"""Check the public package structure and local Markdown links, not skill judgment."""
from pathlib import Path
import re,sys,xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[1]
errors=[]
for p in root.rglob('*'):
    if '.git' in p.relative_to(root).parts: continue
    if p.is_symlink(): errors.append(f'Symlink: {p.relative_to(root)}')
for entry in (root/'skills').glob('*/SKILL.md'):
    text=entry.read_text()
    if not text.startswith('---\n') or len(text.split('---',2))<3:
        errors.append(f'Missing frontmatter: {entry}')
    else:
        front=text.split('---',2)[1]
        if not re.search(r'^name:\s*'+re.escape(entry.parent.name)+r'\s*$',front,re.M): errors.append('Skill name mismatch')
        if not re.search(r'^description:\s*\S',front,re.M): errors.append('Missing description')
for p in root.rglob('*.md'):
    if '.git' in p.relative_to(root).parts: continue
    for target in re.findall(r'\[[^\]\n]*\]\(([^)\n]+)\)',p.read_text()):
        target=target.strip('<>')
        if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:',target) or target.startswith('#'): continue
        name=target.split('#',1)[0]
        if name and not (p.parent/name).exists(): errors.append(f'Broken link in {p.relative_to(root)}: {target}')
for p in (root/'assets').glob('*.svg'):
    try: ET.parse(p)
    except ET.ParseError as exc: errors.append(str(exc))
if not list((root/'skills').glob('*/SKILL.md')): errors.append('No skill entrypoint')
if errors:
    print('\n'.join(errors));sys.exit(1)
print('Package structure, local link targets and SVG syntax pass; behavioral quality is not assessed.')
