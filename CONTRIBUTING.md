# Contributing to Enterprise Council AI

Thank you for your interest in contributing to Enterprise Council AI! This guide will help you get started.

## Development Setup

### Prerequisites
- Python 3.10+
- Git

### Local Environment
```bash
git clone https://github.com/anishanandhan/Enterprise-council.git
cd Enterprise-council
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-cov httpx
```

### Running Tests
```bash
pytest tests/ -v --tb=short
```

### Running the Application
```bash
# Start the API server
venv/bin/uvicorn api.main:app --port 8001 --reload

# Start the Streamlit dashboard
streamlit run frontend/app.py
```

## Code Style

- **Python**: Follow PEP 8 conventions.
- **Docstrings**: Use descriptive docstrings for all public functions and classes.
- **Type Hints**: Use type hints where practical for function parameters and return values.
- **Imports**: Group imports in order: standard library, third-party, local.

## Branching Strategy

1. **`main`** — Production-ready code. Protected branch.
2. **`feature/*`** — Feature branches for new functionality.
3. **`fix/*`** — Bug fix branches.

## Pull Request Process

1. Fork the repository and create your branch from `main`.
2. Write or update tests for any changed functionality.
3. Ensure all tests pass: `pytest tests/ -v`.
4. Update documentation if your changes affect user-facing behavior.
5. Submit a pull request with a clear description of changes.

### PR Checklist
- [ ] Tests pass locally
- [ ] Code follows project style guidelines
- [ ] Docstrings added/updated for changed functions
- [ ] README updated if applicable
- [ ] No sensitive data (API keys, passwords) committed

## Reporting Issues

- Use GitHub Issues with the appropriate labels.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
