# claude-code-hooks

## About
claude-code-hooks is a General Python project.

## Project Structure
```
claude-code-hooks/
├── src/          # Source code
├── outcomes/     # Output files
├── .env          # Environment variables (not committed)
├── .env.example  # Environment variable template
├── requirements.txt
└── README.md
```

## Setup
1. Create and activate virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your actual values
```

## Usage
```bash
PYTHONPATH=src python3 src/main.py
```
