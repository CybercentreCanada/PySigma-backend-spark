"""
    This module implements the Spark SQL backend using pysigma
"""
import copy
import re
from enum import Enum
from typing import Any, ClassVar, Dict, Optional, Pattern, Tuple, Union

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionSelector,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaString


class SourceType(str, Enum):
    TABLE = "table"
    VIEW = "view"


class SparkSQLBackend(TextQueryBackend):
    """Spark SQL backend."""

    name: ClassVar[str] = "Spark SQL Backend"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain Spark SQL expressions",
    }

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem, ConditionItem]] = (  # type: ignore
        ConditionNOT,
        ConditionAND,
        ConditionOR,
        ConditionSelector,
    )
    group_expression: ClassVar[Optional[str]] = "({expr})"

    # or_token: ClassVar[str] = "OR"
    # and_token: ClassVar[str] = "AND"
    # not_token: ClassVar[str] = "NOT"
    # eq_token: ClassVar[str] = " ILIKE "
    or_token: ClassVar[Optional[str]] = "OR"
    and_token: ClassVar[Optional[str]] = "AND"
    not_token: ClassVar[Optional[str]] = "NOT"
    eq_token: ClassVar[Optional[str]] = " ILIKE "

    field_quote: ClassVar[Optional[str]] = "`"
    field_quote_pattern: ClassVar[Optional[Pattern]] = re.compile(r"^[\.\[\]a-zA-Z0-9_]*$")
    field_quote_pattern_negation: ClassVar[bool] = True

    field_escape = "\\"
    field_escape_quote = True

    str_quote: ClassVar[str] = "'"
    escape_char: ClassVar[Optional[str]] = "\\"
    wildcard_multi: ClassVar[Optional[str]] = "%"
    wildcard_single: ClassVar[Optional[str]] = "_"
    add_escaped: ClassVar[str] = "\\'"

    re_expression: ClassVar[Optional[str]] = "regexp({field}, '{regex}')"
    re_escape_char: ClassVar[Optional[str]] = "\\"
    re_escape: ClassVar[Tuple[str, str]] = ('"', "'")  # type: ignore

    compare_op_expression: ClassVar[Optional[str]] = "{field}{operator}{value}"
    compare_operators: ClassVar[Optional[Dict[SigmaCompareExpression.CompareOperators, str]]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    field_null_expression: ClassVar[Optional[str]] = "{field} IS NULL"

    convert_or_as_in: ClassVar[bool] = False
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = True
    field_in_list_expression: ClassVar[Optional[str]] = "{field} {op} ({list})"

    or_in_operator: ClassVar[Optional[str]] = "IN"
    list_separator: ClassVar[Optional[str]] = ", "

    unbound_value_str_expression: ClassVar[Optional[str]] = "{value}"
    unbound_value_num_expression: ClassVar[Optional[str]] = "{value}"
    unbound_value_re_expression: ClassVar[Optional[str]] = "{value}"

    deferred_start: ClassVar[Optional[str]] = "\n| "
    deferred_separator: ClassVar[Optional[str]] = "\n| "
    deferred_only_query: ClassVar[Optional[str]] = "*"

    identifier = "spark"
    active = True
    config_required = False
    default_config = ["sysmon"]

    parenthesize: bool = True

    indent: str = 4 * " "

    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = True,
    ):
        super().__init__(collect_errors=collect_errors, processing_pipeline=processing_pipeline)

    def indent_block(self, text: str, n: int) -> str:
        """
        Insert `n` spaces before each line.

        :param text: string to indent
        :param n: number of spaces to insert
        :returns: indented block
        """
        return "\n".join(n * " " + line for line in text.split("\n"))

    def convert(
        self,
        rule_collection: SigmaCollection,
        output_format: str | None = None,
        source_type: SourceType = SourceType.TABLE,
    ) -> Any:
        """
        Convert a Sigma ruleset into the target data structure.

        :param rule_collection: SigmaCollection to convert
        :param output_format: desired format
        :returns: backend output
        :raises ValueError: unrecognized output_format value
        """
        queries = [
            query for rule in rule_collection.rules for query in self.convert_rule(rule, source_type=source_type)
        ]
        return self.finalize_output_default(queries)

    def convert_rule(
        self, rule: SigmaRule, output_format: str | None = None, source_type: SourceType = SourceType.TABLE
    ) -> Any:
        """
        Convert a single Sigma rule into the target data structure (usually query, see above).
        """
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
            queries = [
                self.convert_condition(cond.parsed, states[index])
                for index, cond in enumerate(rule.detection.parsed_condition)
            ]

            error_state = "finalizing query for"
            return [  # 3. Postprocess generated query
                self.finalize_query_spark(
                    query,
                    source_type,
                )
                for query in queries
            ]
        except SigmaError as e:
            if self.collect_errors:
                self.errors.append((rule, e))
                return []
            else:
                raise
        except Exception as e:  # enrich all other exceptions with Sigma-specific context information
            msg = f" (while {error_state} rule {str(rule.source)})"
            if len(e.args) > 1:
                e.args = (e.args[0] + msg,) + e.args[1:]
            else:
                e.args = (e.args[0] + msg,)
            raise

    def finalize_query_spark(
        self,
        query: str | DeferredQueryExpression,
        source_type: SourceType = SourceType.TABLE,
    ) -> str:
        source = self.last_processing_pipeline.state.get("source", {}).get(source_type) or "--SOURCE"
        return f"SELECT * FROM {source} WHERE {query}"

    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """Convert a SigmaString into a plain string which can be used in query."""
        converted = s.convert(
            self.escape_char,
            self.wildcard_multi,
            self.wildcard_single,
            self.add_escaped,
            self.filter_chars,
        )
        converted = converted.replace("\\\\", "\\\\\\\\")

        if self.decide_string_quoting(s):
            return self.quote_string(converted)
        else:
            return converted

    def escape_string(self, s: str) -> str:
        """
        Escape occurrences of str_quote and escape_char with escape_char.

        Intended for 'normal' strings, i.e. not after ILIKE or in regular expressions.
        """
        if self.escape_char is None:
            raise ValueError("escape_char must be specified on backend")

        return s.replace(self.escape_char, self.escape_char * 2).replace(
            self.str_quote, self.escape_char + self.str_quote
        )
