import re
from pathlib import Path

import pytest


@pytest.fixture
def log_path(request):
    log_dir = Path(request.node.path).parent / "logs"
    name = request.node.name
    if request.node.cls:
        name = f"{request.node.cls.__name__}.{name}"
    name = re.sub(r"[^\w.-]", "_", name)
    path = log_dir / f"{name}.txt"
    path.unlink(missing_ok=True)
    return path
