import os
import sys
import fnmatch

# --- CONFIGURATION ---
IGNORE_DIRS = {'.git', '.wrangler', 'node_modules', '__pycache__', 'venv', '.vscode', '.idea'}
IGNORE_FILES = {'package-lock.json', '.DS_Store', 'Thumbs.db', '*.log', '*.png', '*.jpg'}
TEXT_EXTENSIONS = {'.ts', '.js', '.py', '.json', '.toml', '.md', '.sql', '.txt', '.html', '.css'}
ALERT_ICON = "🔴"
WARN_ICON = "🟡"

def is_ignored(path):
    name = os.path.basename(path)
    if name in IGNORE_DIRS: return True
    if any(fnmatch.fnmatch(name, p) for p in IGNORE_FILES): return True
    return False

def generate_mermaid_tree(start_path):
    lines = ["```mermaid", "graph TD;"]
    path_map = {start_path: "root"}
    root_name = os.path.basename(os.path.abspath(start_path))
    lines.append(f"    root[{root_name}];")
    for root, dirs, files in os.walk(start_path):
        dirs[:] = [d for d in dirs if not is_ignored(os.path.join(root, d))]
        current_id = path_map.get(root, "root")
        for d in dirs:
            full = os.path.join(root, d)
            nid = f"d_{abs(hash(full))}"
            path_map[full] = nid
            lines.append(f"    {current_id} --> {nid}[📂 {d}];")
        for f in files:
            if not is_ignored(f) and os.path.splitext(f)[1] in TEXT_EXTENSIONS:
                full = os.path.join(root, f)
                nid = f"f_{abs(hash(full))}"
                lines.append(f"    {current_id} --> {nid}[📄 {f}];")
    lines.append("```")
    return "\n".join(lines)

def analyze_health(content):
    issues = []
    if "<<<<<<< HEAD" in content: issues.append(f"{ALERT_ICON} **CRITICAL**: Merge Conflict!")
    if "AIzaSy" in content or ("sk-" in content and "sk-proj" not in content):
        issues.append(f"{ALERT_ICON} **SECURITY**: Potential API Key found!")
    if "TODO" in content: issues.append(f"{WARN_ICON} TODO found.")
    return issues

def scan_directory(start_path, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# Context Report\nTarget: `{os.path.abspath(start_path)}`\n\n")
        print("🎨 Generating visual map...")
        f.write("## 1. Visual Map\n" + generate_mermaid_tree(start_path) + "\n\n")
        print("🔍 Analyzing files...")
        f.write("## 2. File Content\n")
        for root, dirs, files in os.walk(start_path):
            dirs[:] = [d for d in dirs if not is_ignored(os.path.join(root, d))]
            for file in files:
                if is_ignored(file): continue
                if os.path.splitext(file)[1] in TEXT_EXTENSIONS:
                    path = os.path.join(root, file)
                    f.write(f"\n--- FILE: {file} ---\n")
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as r:
                            content = r.read()
                            issues = analyze_health(content)
                            if issues: 
                                f.write("\n> **Health Check:**\n" + "\n".join([f"> {i}" for i in issues]) + "\n\n")
                            f.write(f"```\n{content}\n```\n")
                    except: pass
    print("Done!")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    scan_directory(target, "context_report.md")
