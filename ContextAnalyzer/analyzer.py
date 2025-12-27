import os
import argparse
import fnmatch
from pathlib import Path

# Extensions to ignore (media, binary, etc.)
IGNORE_EXTENSIONS = {
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.tiff', '.webp',
    # Video/Audio
    '.mp4', '.mkv', '.avi', '.mov', '.mp3', '.wav', '.flac', '.aac',
    # Archives/Binaries
    '.zip', '.tar', '.gz', '.7z', '.rar', '.exe', '.dll', '.so', '.dylib', '.bin', '.iso',
    # Python/System
    '.pyc', '.pyo', '.pyd', '.db', '.sqlite', '.sqlite3'
}

# Directories to always ignore
IGNORE_DIRS = {'.git', '__pycache__', 'node_modules', '.idea', '.vscode', 'venv', 'env', '.gemini'}

def load_gitignore(root_path):
    """Reads .gitignore and returns a list of patterns."""
    gitignore_path = root_path / '.gitignore'
    patterns = []
    if gitignore_path.exists():
        try:
            with open(gitignore_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        patterns.append(line)
        except Exception as e:
            print(f"Warning: Could not read .gitignore: {e}")
    return patterns

def should_ignore(path, root_path, gitignore_patterns):
    """Checks if a path should be ignored based on global rules and gitignore."""
    name = path.name
    rel_path = str(path.relative_to(root_path)).replace(os.sep, '/')

    # 1. Check strict directory ignores
    if path.is_dir() and name in IGNORE_DIRS:
        return True
    
    # Check if any parent part is in IGNORE_DIRS (optimization for deep files)
    for part in path.parts:
        if part in IGNORE_DIRS:
            return True

    # 2. Check extensions (only for files)
    if path.is_file() and path.suffix.lower() in IGNORE_EXTENSIONS:
        return True
        
    # 3. Check gitignore patterns
    # We need to check if the path or any of its parents matches a pattern
    # fnmatch isn't perfect for gitignore rules (e.g. negation), but it serves 90% of cases.
    # For a robust solution, we'd need a proper gitignore parser, but this is a lightweight script.
    
    for pattern in gitignore_patterns:
        # Handle directory-specific patterns (ending with /)
        if pattern.endswith('/'):
            if path.is_dir() and fnmatch.fnmatch(name, pattern[:-1]):
                return True
            if fnmatch.fnmatch(rel_path + '/', pattern): # Match 'dir/' against 'dir/'
                 return True
        else:
            if fnmatch.fnmatch(name, pattern):
                return True
            if fnmatch.fnmatch(rel_path, pattern):
                return True
            
    return False

def generate_tree(root_path, gitignore_patterns):
    """Generates a tree-like string structure."""
    tree_lines = []
    
    def _add_to_tree(directory, prefix=''):
        original_contents = list(directory.iterdir())
        # Sort: directories first, then files
        contents = []
        for p in original_contents:
             if not should_ignore(p, root_path, gitignore_patterns):
                 contents.append(p)
        
        contents.sort(key=lambda x: (not x.is_dir(), x.name.lower()))
        
        count = len(contents)
        for i, path in enumerate(contents):
            is_last = (i == count - 1)
            connector = '└── ' if is_last else '├── '
            tree_lines.append(f"{prefix}{connector}{path.name}")
            
            if path.is_dir():
                extension = '    ' if is_last else '│   '
                _add_to_tree(path, prefix + extension)

    tree_lines.append(root_path.name + "/")
    _add_to_tree(root_path)
    return "\n".join(tree_lines)

def get_files_recursively(root_path, gitignore_patterns):
    """Yields valid files recursively."""
    for root, dirs, files in os.walk(root_path):
        # Filter directories in-place to prevent os.walk from entering them
        # We need to convert to Path for consistent checking
        root_p = Path(root)
        
        # Determine strict ignore dirs first to modify dirs list
        # This is a bit tricky with os.walk since we need to check full paths against our should_ignore
        # But should_ignore checks the full relative path.
        
        # Let's filter dirs manually
        # modifying the 'dirs' list in-place tells os.walk to skip them
        dirs[:] = [d for d in dirs if not should_ignore(root_p / d, root_path, gitignore_patterns)]
        
        for file in files:
            file_path = root_p / file
            if not should_ignore(file_path, root_path, gitignore_patterns):
                yield file_path

def generate_report(target_dir, output_file):
    root_path = Path(target_dir).resolve()
    gitignore_patterns = load_gitignore(root_path)
    
    print(f"Analyzing: {root_path}")
    print(f"Output to: {output_file}")
    
    report_content = []
    
    # 1. Header
    report_content.append("# Context Report")
    report_content.append(f"\nTarget: `{root_path}`")
    
    # 2. Tree Structure
    print("Generating tree...")
    tree_str = generate_tree(root_path, gitignore_patterns)
    report_content.append("\n## Project Structure")
    report_content.append("```text")
    report_content.append(tree_str)
    report_content.append("```")
    
    # 3. File Contents
    print("Reading files...")
    report_content.append("\n## File Contents")
    
    files = list(get_files_recursively(root_path, gitignore_patterns))
    # Sort files by path for deterministic output
    files.sort(key=lambda p: str(p.relative_to(root_path)))
    
    for file_path in files:
        rel_path = file_path.relative_to(root_path)
        report_content.append(f"\n--- FILE: {rel_path} ---")
        
        # Determine language for markdown syntax highlighting (dumb heuristic)
        ext = file_path.suffix.lower()
        lang = ''
        if ext == '.py': lang = 'python'
        elif ext == '.js': lang = 'javascript'
        elif ext == '.ts': lang = 'typescript'
        elif ext == '.html': lang = 'html'
        elif ext == '.css': lang = 'css'
        elif ext == '.json': lang = 'json'
        elif ext == '.md': lang = 'markdown'
        elif ext == '.sql': lang = 'sql'
        elif ext == '.sh': lang = 'bash'
        
        report_content.append(f"\n```{lang}")
        
        try:
            text = file_path.read_text(encoding='utf-8', errors='replace')
            report_content.append(text)
        except Exception as e:
            report_content.append(f"[Error reading file: {e}]")
            
        report_content.append("```")

    # Write Report
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(report_content))
    
    print("Done!")

def main():
    parser = argparse.ArgumentParser(description="Generate a context report for a codebase.")
    parser.add_argument("path", nargs='?', default=".", help="Path to the directory to analyze (default: current directory)")
    parser.add_argument("-o", "--output", default="context_report.md", help="Output file name (default: context_report.md)")
    
    args = parser.parse_args()
    
    target_path = args.path
    if not os.path.exists(target_path):
        print(f"Error: Directory '{target_path}' does not exist.")
        return

    generate_report(target_path, args.output)

if __name__ == "__main__":
    main()
