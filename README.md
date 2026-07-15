# authenticated_exchanges
Companion repo for the Teardown 2026 workshop "Authenticated Exchanges"

## Setup

Opening this repo in a GitHub Codespace will automatically create a virtual
env and install dependencies (see `.devcontainer/devcontainer.json`).

To set up locally instead:

```bash
python3 -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

Each exercise's tests are run from within that exercise's directory, e.g.:

```bash
cd ex1-static-uid
pytest
```
