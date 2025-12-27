import os
import sys
import fnmatch

# --- CONFIGURATION ---
IGNORE_DIRS = {'.git', '.wrangler', 'node_modules', '__pycache__', 'venv', '.vscode', '.idea'}
IGNORE_FILES = {'package-lock.json', '.DS_Store', 'Thumbs.db', '*.log', '*.png', '*.jpg'}
# File extensions to read (code)
TEXT_EXTENSIONS = {'.ts', '.js', '.py', '.json', '.toml', '.md', '.sql', '.txt', '.html', '.css'}

# --- COLORS AND ICONS ---
ALERT_ICON = "🔴"
WARN_ICON = "🟡"
OK_ICON = "🟢"

def is_ignored(path):
    """Checks if a file or folder should be ignored."""
    name = os.path.basename(path)
    if name in IGNORE_DIRS:
        return True
    if any(fnmatch.fnmatch(name, pattern) for pattern in IGNORE_FILES):
        return True
    return False

def generate_mermaid_tree(start_path):
    """Generates Mermaid diagram code for structure visualization."""
    lines = ["```mermaid", "graph TD;"]
    root_name = os.path.basename(os.path.abspath(start_path))
    # Use path hashes for node IDs to avoid special character issues
    path_map = {start_path: "root"}
    lines.append(f"    root[{root_name}];")

    for root, dirs, files in os.walk(start_path):
        dirs[:] = [d for d in dirs if not is_ignored(os.path.join(root, d))]
        
        current_id = path_map.get(root, "root")
        
        # Folder links
        for d in dirs:
            full_path = os.path.join(root, d)
            node_id = f"dir_{abs(hash(full_path))}"
            path_map[full_path] = node_id
            lines.append(f"    {current_id} --> {node_id}[📂 {d}];")
            
        # File links (show only relevant code files to keep diagram clean)
        for f in files:
            if not is_ignored(f) and os.path.splitext(f)[1] in TEXT_EXTENSIONS:
                full_path = os.path.join(root, f)
                node_id = f"file_{abs(hash(full_path))}"
                lines.append(f"    {current_id} --> {node_id}[📄 {f}];")
                
    lines.append("```")
    return "\n".join(lines)

def analyze_health(content, filename):
    """Scans for potential errors and security issues."""
    issues = []
    
    # 1. Search for forgotten Git merge conflicts
    if "<<<<<<< HEAD" in content:
        issues.append(f"{ALERT_ICON} **CRITICAL**: Git Merge Conflict markers found!")

    # 2. Search for hardcoded API keys (basic protection)
    if "AIzaSy" in content: # Example Google key
        issues.append(f"{ALERT_ICON} **SECURITY**: Google API key appears to be hardcoded!")
    if "sk-" in content and "sk-proj" not in content: # Example OpenAI key
        issues.append(f"{ALERT_ICON} **SECURITY**: Possible OpenAI key found!")

    # 3. Search for TODO and FIXME
    if "TODO" in content:
        issues.append(f"{WARN_ICON} TODO markers found.")
    if "FIXME" in content:
        issues.append(f"{WARN_ICON} FIXME markers found.")

    return issues

def scan_directory(start_path, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        # Header
        f.write(f"# DeepContext Report\n\n")
        f.write(f"Target: `{os.path.abspath(start_path)}`\n\n")
        
        # 1. Visual Map (Mermaid)
        print("🎨 Generating visual map...")
        f.write("## 1. Visual Map (Mermaid)\n")
        f.write("_Copy this code into a Mermaid viewer or GitHub to see the graph._\n\n")
        f.write(generate_mermaid_tree(start_path))
        f.write("\n\n")

        # 2. Text Tree (Classic)
        f.write("## 2. File Structure\n```text\n")
        for root, dirs, files in os.walk(start_path):
            dirs[:] = [d for d in dirs if not is_ignored(os.path.join(root, d))]
            level = root.replace(start_path, '').count(os.sep)
            indent = ' ' * 4 * (level)
            f.write(f"{indent}{os.path.basename(root)}/\n")
            subindent = ' ' * 4 * (level + 1)
            for file in files:
                if not is_ignored(file):
                    f.write(f"{subindent}{file}\n")
        f.write("```\n\n")

        # 3. File Content + Health Analysis
        print("🔍 Analyzing code health...")
        f.write("## 3. Code Analysis & Content\n")
        
        for root, dirs, files in os.walk(start_path):
            dirs[:] = [d for d in dirs if not is_ignored(os.path.join(root, d))]
            for file in files:
                if is_ignored(file): continue
                
                file_path = os
            
