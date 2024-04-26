from .array import ArraySparkSQLBackend
from .spark import SourceType, SparkSQLBackend

backends = {
    "spark": SparkSQLBackend,
    "array": ArraySparkSQLBackend,
}

__version__ = "0.0.1"
