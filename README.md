## pySigma-backend-spark
## Description
This is a Spark SQL backend for pySigma. It provides the package `sigma.backends.spark` with the `SparkSQLBackend` and
`ArraySparkSQLBackend` classes.

## Installation
It is recommended to create a python venv in the root folder of the repo:
```bash
git clone git@gitlab.chimera.cyber.gc.ca:CCCSA/pysigma-backend-spark.git
cd pysigma-backend-spark
python -m venv .venv
source .venv/bin/activate
pip install .
```
`-e` can be added before `.` to install in editable mode and `[dev]` can be added directly after `.` to install dev dependencies.
```bash
pip install -e .[dev]
```

## Example Usage
```python
from sigma.backends.spark import ArraySparkSQLBackend, SparkSQLBackend
from sigma.collection import SigmaCollection

rule = SigmaCollection.from_yaml(
    """\
title: Test
logsource:
    category: test
    product: windows
detection:
    selection:
        field1: value1
        field2|contains: value2
    condition: selection
"""
)

assert SparkSQLBackend().convert(rule) == [
    "SELECT * FROM --SOURCE WHERE field1 ILIKE 'value1' AND field2 ILIKE '%value2%'"
]

assert (
    ArraySparkSQLBackend().convert(rule)
    == """\
SELECT
    *,
    map_keys(
    map_filter(
    map(
        'Test',
        (field1 ILIKE 'value1' AND field2 ILIKE '%value2%')
    )
    , (k,v) -> v = TRUE)) as sigma_final
FROM
    --SOURCE
"""
)
```