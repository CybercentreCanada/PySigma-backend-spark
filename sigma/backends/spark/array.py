import copy
import textwrap
from typing import ClassVar

from sigma.collection import SigmaCollection
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from .spark import SourceType, SparkSQLBackend


class ArraySparkSQLBackend(SparkSQLBackend):
    """Array Spark SQL backend."""

    name: ClassVar[str] = "Array Spark SQL Backend"
    identifier = "array"
    formats: ClassVar[dict[str, str]] = {
        "default": "Create an array column of rules that hit",
    }

    def convert(
        self,
        rule_collection: SigmaCollection,
        output_format: str | None = None,
        source_type: SourceType = SourceType.TABLE,
    ) -> str:
        queries = [query for rule in rule_collection.rules if (query := self.convert_rule(rule)) is not None]
        return self.finalize_output_array(queries, source_type)

    def convert_rule(
        self,
        rule: SigmaRule,
        output_format: str | None = None,
        *args,
        **kwargs,
    ) -> str | None:
        try:
            rule = copy.deepcopy(rule)
            self.last_processing_pipeline = self.backend_processing_pipeline + self.processing_pipeline

            error_state = "applying processing pipeline on"
            self.last_processing_pipeline.apply(rule)  # 1. Apply transformations

            # 2. Convert conditions
            error_state = "converting"
            states = [
                ConversionState(processing_state=dict(self.last_processing_pipeline.state))
                for _ in rule.detection.parsed_condition
            ]
            conditions = f" {self.or_token} ".join(
                self.group_expression.format(expr=self.convert_condition(cond.parsed, state=states[index]))
                for index, cond in enumerate(rule.detection.parsed_condition)
            )
            return f"""\
{self.quote_string(self.escape_string(rule.title))},
{conditions}"""
        except SigmaError as e:
            if self.collect_errors:
                self.errors.append((rule, e))
                return None
            else:
                raise
        except Exception as e:  # enrich all other exceptions with Sigma-specific context information
            msg = f" (while {error_state} rule {str(rule.source)})"
            if len(e.args) > 1:
                e.args = (e.args[0] + msg,) + e.args[1:]
            else:
                e.args = (e.args[0] + msg,)
            raise

    def finalize_output_array(
        self,
        queries: list[str],
        source_type: SourceType,
    ) -> str:
        map_entries = ",\n".join(queries)
        source = self.last_processing_pipeline.state.get("source", {}).get(source_type) or "--SOURCE"
        return f"""\
SELECT
    *,
    map_keys(
    map_filter(
    map(
{textwrap.indent(map_entries, ' ' * 8)}
    )
    , (k,v) -> v = TRUE)) as sigma_final
FROM
    {source}
"""
