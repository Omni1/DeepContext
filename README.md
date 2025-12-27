DeepContext
DeepContext is a lightweight, powerful tool designed to package your codebase into AI-ready Markdown. It recursively analyzes your project, generating a single context report that includes a visual file tree and the contents of your files, optimized for LLM consumption.

Features
Automatic Tree Generation: Visualizes your project structure at a glance.
Smart .gitignore Respect: Automatically parses and respects your .gitignore rules to exclude irrelevant files.
Media & Binary Filtering: Intelligently ignores media (images, video, audio) and binary files to keep the context clean and text-focused.
Modular & Clean: Written in pure Python with no external dependencies.
Quick Start
To generate a context report for the current directory:

python analyzer.py
This will create a context_report.md file in the same directory.

Advanced Usage
You can specify a target directory and a custom output filename:

python analyzer.py /path/to/project -o my_codebase_context.md
Usage
Drop analyzer.py into your project or keep it in a tools directory.
Run the script pointing to your target codebase.
Upload the generated Markdown file to your AI assistant.
Requirements
Python 3.6+
