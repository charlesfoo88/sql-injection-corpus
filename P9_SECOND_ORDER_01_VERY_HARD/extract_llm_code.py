"""
Extract Python code from LLM response HTML files for P9
"""
import re
from pathlib import Path
from html.parser import HTMLParser

class CodeExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.code_blocks = []
        self.in_code = False
        self.current_code = []
        
    def handle_data(self, data):
        # Look for Python code patterns
        if any(pattern in data for pattern in ['def ', 'import ', 'from ', 'class ', 'psycopg2', 'sql.Identifier']):
            self.current_code.append(data)
        if '\n' in data and self.current_code:
            code = ''.join(self.current_code)
            if len(code.strip()) > 50:  # Meaningful code block
                self.code_blocks.append(code)
            self.current_code = []

def extract_from_html(html_file):
    """Extract code from HTML file"""
    with open(html_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Remove HTML tags but keep content
    text = re.sub(r'<[^>]+>', '\n', content)
    
    # Find Python code blocks (look for function definitions and imports)
    code_blocks = []
    lines = text.split('\n')
    
    current_block = []
    in_code = False
    
    for line in lines:
        # Start of code block indicators
        if any(pattern in line for pattern in ['import psycopg2', 'from psycopg2', 'def ', 'class ']):
            in_code = True
            current_block = [line]
        elif in_code:
            # Continue collecting code
            if line.strip() and not line.strip().startswith('#'):
                current_block.append(line)
            # End of code block
            if len(current_block) > 5 and (not line.strip() or 'Explanation' in line or 'Summary' in line):
                code = '\n'.join(current_block)
                if 'def ' in code and len(code) > 100:
                    code_blocks.append(code)
                current_block = []
                in_code = False
    
    return code_blocks

def main():
    base_dir = Path(__file__).parent
    llm_responses = base_dir / 'llm_responses'
    
    # Extract ChatGPT (OpenAI) code
    print("Extracting ChatGPT code...")
    chatgpt_html = llm_responses / 'OpenAI P09_01.htm'
    chatgpt_blocks = extract_from_html(chatgpt_html)
    
    if chatgpt_blocks:
        output_dir = base_dir / 'llm_extracted' / 'chatgpt_extracted'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save all code blocks
        all_code = '\n\n# ' + '='*70 + '\n\n'.join(chatgpt_blocks)
        (output_dir / 'chatgpt_extracted_code.py').write_text(all_code, encoding='utf-8')
        print(f"  Extracted {len(chatgpt_blocks)} code blocks")
    
    # Extract Gemini (Google) code  
    print("Extracting Gemini code...")
    gemini_html = llm_responses / 'Google P9_01.htm'
    gemini_blocks = extract_from_html(gemini_html)
    
    if gemini_blocks:
        output_dir = base_dir / 'llm_extracted' / 'gemini_extracted'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save all code blocks
        all_code = '\n\n# ' + '='*70 + '\n\n'.join(gemini_blocks)
        (output_dir / 'gemini_extracted_code.py').write_text(all_code, encoding='utf-8')
        print(f"  Extracted {len(gemini_blocks)} code blocks")
    
    print("\nExtraction complete!")
    print(f"Claude: llm_extracted/claude_extracted/")
    print(f"ChatGPT: llm_extracted/chatgpt_extracted/")
    print(f"Gemini: llm_extracted/gemini_extracted/")

if __name__ == '__main__':
    main()
