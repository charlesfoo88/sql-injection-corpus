import re

def fix_python_file(filename):
    """Fix line breaks in extracted Python files."""
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Fix 'from X import\nY' -> 'from X import Y'
    content = re.sub(r'(from [a-zA-Z0-9_.]+ import)\n([A-Z][a-zA-Z0-9_]*)', r'\1 \2', content)
    
    # Fix 'variable =\nvalue' -> 'variable = value'  
    content = re.sub(r'([a-z_]\w*) =\n', r'\1 = ', content)
    
    # Fix 'field =\nmodels.' -> 'field = models.'
    content = re.sub(r' =\nmodels\.', r' = models.', content)
    
    # Fix 'if condition not in\nCLASS' -> 'if condition not in CLASS'
    content = re.sub(r' (not in|in|and|or)\n', r' \1 ', content)
    
    # Fix 'raise Error("...\nmore' -> 'raise Error("... more'
    content = re.sub(r'raise (\w+Error)\("([^"]*)\n([^"]*)"', r'raise \1("\2 \3"', content)
    
    # Fix 'return \nstatement' -> 'return statement'
    content = re.sub(r'return\n', 'return ', content)
    
    # Remove excessive blank lines
    content = re.sub(r'\n\n\n+', '\n\n', content)
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f'Fixed {filename}')

if __name__ == '__main__':
    fix_python_file('models.py')
    fix_python_file('query_builder.py')
    print('Done')
