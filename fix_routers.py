import os, ast, re, json

tags_meta = []

for file in os.listdir('routers'):
    if not file.endswith('.py') or file == '__init__.py': continue
    path = os.path.join('routers', file)
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Get docstring
    try:
        tree = ast.parse(content)
        doc = ast.get_docstring(tree)
        desc = doc.split('\n')[0] if doc else file.replace('.py', '').title()
    except Exception:
        desc = file.replace('.py', '').title()

    # Guess tag name
    tag_name = file.replace('.py', '').title()
    if 'tags=["' in content:
        match = re.search(r'tags=\[\"([^\"]+)\"\]', content)
        if match:
            tag_name = match.group(1)

    tags_meta.append({'name': tag_name, 'description': desc})

    # Add tags to APIRouter()
    if 'router = APIRouter()' in content:
        content = content.replace('router = APIRouter()', f'router = APIRouter(tags=["{tag_name}"])')
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

# Edit main.py
with open('main.py', 'r', encoding='utf-8') as f:
    main_content = f.read()

if 'openapi_tags=' not in main_content:
    tags_str = 'tags_metadata = ' + json.dumps(tags_meta, indent=4) + '\n\n'
    
    # insert before app = FastAPI
    parts = main_content.split('app = FastAPI(\n')
    out = parts[0] + tags_str + 'app = FastAPI(\n    openapi_tags=tags_metadata,\n' + parts[1]
    with open('main.py', 'w', encoding='utf-8') as f:
        f.write(out)

print('Edited routers and main.py successfully!')
