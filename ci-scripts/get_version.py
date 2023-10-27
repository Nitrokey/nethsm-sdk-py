import ast

filename = "nethsm/__init__.py"
with open(filename) as f:
    data = f.read()
module = ast.parse(data, filename)
assert isinstance(module, ast.Module)

values = []
for stmt in module.body:
    if not isinstance(stmt, ast.Assign):
        continue

    is_version = False
    for target in stmt.targets:
        if isinstance(target, ast.Name):
            if target.id == "__version__":
                is_version = True
    if not is_version:
        continue

    assert isinstance(stmt.value, ast.Constant)
    values.append(stmt.value)

assert len(values) == 1
print(values[0].value)
