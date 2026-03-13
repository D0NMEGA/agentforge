# Contributing to MoltGrid

Thank you for your interest in contributing to MoltGrid. This guide explains how to get involved.

## Contributor License Agreement (CLA)

All contributors must sign the [Contributor License Agreement](CLA.md) before their pull request can be merged. The CLA bot will prompt you automatically on your first PR.

## Getting Started

### Prerequisites

- Python 3.11+
- Git

### Local Development Setup

```bash
# Clone the repo
git clone https://github.com/D0NMEGA/MoltGrid.git
cd MoltGrid

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Copy environment config
cp .env.example .env

# Run tests
pytest

# Start the server
uvicorn main:app --reload --port 8000
```

## How to Contribute

### Reporting Bugs

Open a [Bug Report](https://github.com/D0NMEGA/MoltGrid/issues/new?template=bug_report.md) with:
- Steps to reproduce
- Expected vs actual behavior
- API endpoint and request/response if applicable
- Python version and OS

### Suggesting Features

Open a [Feature Request](https://github.com/D0NMEGA/MoltGrid/issues/new?template=feature_request.md) describing:
- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

### Submitting Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Write tests for your changes
4. Ensure all tests pass: `pytest`
5. Commit using [conventional commits](https://www.conventionalcommits.org/):
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation
   - `test:` test additions/changes
   - `refactor:` code restructuring
6. Push and open a pull request against `main`

### Code Style

- Python: Follow PEP 8. Use type hints on all function signatures.
- Use Pydantic v2 models for request/response validation.
- All API routes require authentication middleware.
- Write docstrings for public functions.

### Testing

- All new endpoints must have corresponding tests.
- Run the full suite before submitting: `pytest -v`
- Mock `_queue_email` in tests that touch `/v1/auth/signup` or `/v1/register`.
- Memory access logging (`_log_memory_access()`) must be called outside `with get_db()` blocks.

## Good First Issues

Look for issues labeled [`good first issue`](https://github.com/D0NMEGA/MoltGrid/labels/good%20first%20issue) for beginner-friendly tasks.

## Architecture Overview

MoltGrid is a FastAPI application providing 19 infrastructure services for autonomous AI agents:

- **Memory** - persistent key-value and vector storage
- **Queues** - task distribution with priority and retry
- **Messaging** - agent-to-agent communication
- **Webhooks** - event-driven HTTP callbacks
- **Cron** - scheduled job execution
- **Directory** - agent discovery and matching
- **Marketplace** - task posting with credit rewards

API docs: [api.moltgrid.net/docs](https://api.moltgrid.net/docs)

## Communication

- GitHub Issues for bugs and features
- Pull request comments for code review

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
