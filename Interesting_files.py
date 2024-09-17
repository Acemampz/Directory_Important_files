import sys
import os
from collections import defaultdict
from colorama import Fore, Style, init

# Initialize colorama for Windows compatibility
init(autoreset=True)

# Keywords indicating potentially interesting files
INTERESTING_KEYWORDS = [
    'ajax', 'conn', 'log', 'config', 'admin', 'phpmyadmin', 'functions',
    'import', 'export', 'upload', 'register', 'login', 'logout', 'database', 'system'
]

# Define color codes for different file types
COLORS = {
    '.php': Fore.CYAN,      # PHP files
    '.js': Fore.YELLOW,     # JavaScript files
    '.log': Fore.GREEN,     # Log files
    '.txt': Fore.MAGENTA,   # Text files
    '.css': Fore.BLUE,      # CSS files
    '.json': Fore.WHITE,    # JSON files
    '.xls': Fore.RED,       # Excel files
    '.woff2': Fore.LIGHTYELLOW_EX  # Font files
}

# Define descriptions for each file type from a pentesting perspective
DESCRIPTIONS = {
    '.php': 'PHP files often contain server-side logic and are prone to vulnerabilities like SQL injection, command injection, and file inclusion attacks.',
    '.js': 'JavaScript files can contain sensitive logic and might be vulnerable to client-side attacks like Cross-Site Scripting (XSS).',
    '.log': 'Log files may expose sensitive information, such as user actions or error details, which can assist in further exploitation.',
    '.txt': 'Text files could store configuration information or notes, potentially exposing sensitive details.',
    '.css': 'CSS files are unlikely to contain vulnerabilities themselves but could be used in combination with XSS attacks.',
    '.json': 'JSON files may contain sensitive data structures, and if exposed, could lead to data leakage or API abuse.',
    '.xls': 'Excel files could be used for malicious file upload attacks or contain sensitive data that should not be publicly accessible.',
    '.woff2': 'Font files are generally safe, but misconfigurations may expose unnecessary assets.'
}

def show_help():
    help_text = """
Usage: python3 find_interesting_files.py <path_to_file>

Description:
    This script analyzes a list of file paths from a text file and identifies files that may be interesting from a pentesting perspective. It segregates the output based on file types and highlights each type in different colors.

Arguments:
    <path_to_file> : The path to the text file containing file paths (one per line).
    
Example:
    python3 find_interesting_files.py /path/to/your/file_paths.txt
    """
    print(help_text)

def find_interesting_files(file_path):
    try:
        with open(file_path, 'r') as file:
            files = file.readlines()
        
        interesting_files = []

        for line in files:
            file_name = line.strip()
            # Check if the file name contains any of the interesting keywords
            if any(keyword in file_name.lower() for keyword in INTERESTING_KEYWORDS):
                interesting_files.append(file_name)

        return interesting_files

    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return []

def classify_file(file_name):
    # Extract file extension
    _, file_extension = os.path.splitext(file_name)
    return file_extension

def display_files(interesting_files):
    if not interesting_files:
        print("No interesting files found.")
        return

    # Group files by type (extension)
    files_by_type = defaultdict(list)
    for file in interesting_files:
        file_extension = classify_file(file)
        files_by_type[file_extension].append(file)

    # Display files grouped by type with color coding
    for file_extension, files in files_by_type.items():
        color = COLORS.get(file_extension, Fore.WHITE)  # Default to white if file type not recognized
        description = DESCRIPTIONS.get(file_extension, "Unknown file type; further investigation may be needed.")

        # Print the header for each file type
        print(f"\n{color}{file_extension.upper()} Files:{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}  Description: {description}{Style.RESET_ALL}")

        # Print the list of files for this type
        for file in files:
            print(f"  - {file}")

def main():
    # If no arguments are passed, show help message
    if len(sys.argv) == 1:
        show_help()
        sys.exit(0)

    # Check for help argument
    if len(sys.argv) == 2 and sys.argv[1] in ('--help', '-h'):
        show_help()
        sys.exit(0)

    # Check if file path is provided
    if len(sys.argv) != 2:
        print("Error: Incorrect usage.")
        show_help()
        sys.exit(1)

    # Input text file that contains the list of file paths (taken from command line argument)
    input_file = sys.argv[1]

    # Check if the provided file path is valid
    if not os.path.isfile(input_file):
        print(f"Error: File '{input_file}' does not exist.")
        sys.exit(1)

    # Get the list of interesting files
    interesting_files = find_interesting_files(input_file)

    # Display the results
    display_files(interesting_files)

if __name__ == "__main__":
    main()
