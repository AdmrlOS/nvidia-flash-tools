"""External, separately licensed test inputs; no vendor assets are bundled."""
import os
from pathlib import Path


def vendor_path(relative=''):
    """Use a separately extracted pinned BSP, never a developer's host path."""
    configured = os.environ.get('NVIDIA_VENDOR_ROOT')
    root = Path(configured) if configured else Path(__file__).parent/'downloads/Linux_for_Tegra'
    path = root/relative
    if configured and not path.exists():
        raise FileNotFoundError('NVIDIA_VENDOR_ROOT fixture missing: ' + relative)
    return path


def external_path(variable, default):
    configured = os.environ.get(variable)
    path = Path(configured) if configured else Path(__file__).parent/default
    if configured and not path.is_file():
        raise FileNotFoundError(variable + ' must name an existing file')
    return path
