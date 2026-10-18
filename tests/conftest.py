from safemcp.config import ROOT


def pytest_configure(config):
    # Keep temporary test artifacts inside the project, including on restricted Windows hosts.
    (ROOT / "runtime").mkdir(exist_ok=True)
    if config.option.basetemp is None:
        config.option.basetemp = str(ROOT / "runtime" / "pytest")
