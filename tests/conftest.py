from pathlib import Path

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.spark import ArraySparkSQLBackend, SparkSQLBackend


@pytest.fixture
def backend() -> SparkSQLBackend:
    return SparkSQLBackend()


@pytest.fixture
def array() -> ArraySparkSQLBackend:
    return ArraySparkSQLBackend()


@pytest.fixture
def tests_dir() -> Path:
    return Path(__file__).parent


@pytest.fixture
def rules() -> SigmaCollection:
    return SigmaCollection.merge(
        SigmaCollection.from_yaml(rule)
        for rule in [
            """
title: Suspicious Double File Extention in ParentCommandLine
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentCommandLine|contains:
            - '.doc.lnk'
            - '.docx.lnk'
            - '.pdf.lnk'
    condition: selection""",
            """
title: Test1
logsource:
    category: webserver
    product: windows
detection:
    selection:
        ParentCommandLine|contains:
            - '.doc.lnk'
            - '.docx.lnk'
            - '.pdf.lnk'
    condition: selection""",
            """
title: Test2
logsource:
    category: a
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '.doc.lnk'
            - '.docx.lnk'
            - '.pdf.lnk'
    condition: selection""",
            """
title: Test3
logsource:
    category: b
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '.doc.lnk'
            - '.docx.lnk'
            - '.pdf.lnk'
    condition: selection""",
        ]
    )
