"""Generate a DOT relational-mapping diagram from the canonical SQLAlchemy schema."""
from pathlib import Path
import subprocess

from app.models import Base

root = Path(__file__).resolve().parents[1]
doc = root / 'docs'
lines = [
    'digraph ScamTrace {',
    'graph [rankdir=LR, bgcolor="white", nodesep=.4, ranksep=1.0, splines=polyline];',
    'node [shape=plain, fontname="Arial"];',
    'edge [color="#8ba7aa", arrowsize=.65];',
]

for table in Base.metadata.sorted_tables:
    fields = []
    for column in table.columns:
        tags = []
        if column.primary_key:
            tags.append('PK')
        if column.foreign_keys:
            tags.append('FK')
        suffix = f" [{' / '.join(tags)}]" if tags else ''
        fields.append(column.name + suffix)
    rows = ''.join(f'<TR><TD ALIGN="LEFT">{field}</TD></TR>' for field in fields)
    label = f'<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0"><TR><TD BGCOLOR="#15545a"><FONT COLOR="white"><B>{table.name}</B></FONT></TD></TR>{rows}</TABLE>>'
    lines.append(f'"{table.name}" [label={label}];')

for table in Base.metadata.sorted_tables:
    for column in table.columns:
        for foreign_key in column.foreign_keys:
            parent = foreign_key.column.table.name
            lines.append(f'"{parent}" -> "{table.name}";')

lines.append('}')
dot_file = doc / 'Relational_Mapping.dot'
dot_file.write_text('\n'.join(lines), encoding='utf-8')
subprocess.run(['dot', '-Tpng', '-Gdpi=150', str(dot_file), '-o', str(doc / 'Relational_Mapping.png')], check=True)
print('Generated relational mapping for', len(Base.metadata.tables), 'tables')
