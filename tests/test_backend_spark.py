from sigma.backends.spark import SourceType, SparkSQLBackend
from sigma.collection import SigmaCollection
from sigma.conversion.base import ProcessingPipeline
from sigma.pipelines.common import logsource_windows_process_creation
from sigma.processing.pipeline import ProcessingItem
from sigma.processing.transformations import SetStateTransformation


def single_rule_output_to_query(output: list[str]) -> str:
    return output[0].removeprefix("""SELECT * FROM --SOURCE WHERE """)


trivial_rule = SigmaCollection.from_yaml(
    """\
title: Test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Foo: bar
    condition: selection"""
)


def test_output_to_query(backend: SparkSQLBackend):
    output = backend.convert(trivial_rule)
    assert single_rule_output_to_query(output) == "Foo ILIKE 'bar'"


def test_single_quote(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    r"""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        Image|endswith: \pcalua.exe
                        CommandLine|contains: ' -a'
                    condition: selection
                """
                )
            )
        )
        == r"Image ILIKE '%\\\\pcalua.exe' AND CommandLine ILIKE '% -a%'"
    )


def test_triple_quote(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: fo'"o
                    condition: selection
            """
                )
            )
        )
        == "field ILIKE 'fo\\'\"o'"
    )


def test_leql_detection_definition_output_format(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: foo
                    condition: selection
            """
                ),
            )
        )
        == "field ILIKE 'foo'"
    )


def test_not_condition_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: foo
                    filter:
                        field: blah
                    condition: selection and not filter
            """
                )
            )
        )
        == "field ILIKE 'foo' AND (NOT field ILIKE 'blah')"
    )


def test_simple_contains_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|contains: foo
                    condition: selection
            """
                )
            )
        )
        == "field ILIKE '%foo%'"
    )


def test_simple_startswith_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|startswith: foo
                    condition: selection
            """
                )
            )
        )
        == "field ILIKE 'foo%'"
    )


def test_simple_endswith_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|endswith: foo
                    condition: selection
            """
                )
            )
        )
        == "field ILIKE '%foo'"
    )


def test_value_in_list_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field:
                            - val1
                            - val2
                            - val3
                    condition: selection
            """
                )
            )
        )
        == "field ILIKE 'val1' OR field ILIKE 'val2' OR field ILIKE 'val3'"
    )


def test_value_eq_or_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field1: val1
                    selection2:
                        field2: val2
                    condition: selection or selection2
            """
                )
            )
        )
        == "field1 ILIKE 'val1' OR field2 ILIKE 'val2'"
    )


def test_keyword_or_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        - val1
                        - val2
                    condition: selection
            """
                )
            )
        )
        == "'val1' OR 'val2'"
    )


def test_keyword_and_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection1:
                        - val1
                    selection2:
                        - val2
                    condition: selection1 and selection2
            """
                )
            )
        )
        == "'val1' AND 'val2'"
    )


def test_value_eq_and_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: val1
                    selection2:
                        field2: val2
                    condition: selection and selection2
            """
                )
            )
        )
        == "field ILIKE 'val1' AND field2 ILIKE 'val2'"
    )


def test_contains_any_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|contains:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """
                )
            )
        )
        == "field ILIKE '%val1%' OR field ILIKE '%val2%' OR field ILIKE '%val3%'"
    )


def test_contains_all_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|contains|all:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """
                )
            )
        )
        == "field ILIKE '%val1%' AND field ILIKE '%val2%' AND field ILIKE '%val3%'"
    )


def test_startswith_any_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|startswith:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """
                )
            )
        )
        == "field ILIKE 'val1%' OR field ILIKE 'val2%' OR field ILIKE 'val3%'"
    )


def test_endswith_any_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|endswith:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """
                )
            )
        )
        == "field ILIKE '%val1' OR field ILIKE '%val2' OR field ILIKE '%val3'"
    )


def test_re_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|re: boo.*far
                    condition: selection
            """
                )
            )
        )
        == "regexp(field, 'boo.*far')"
        # == "re.search(re.compile(br'boo.*far'),field)"
    )


def test_re_query_with_backslashes(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    r"""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|re: C:\\foo.*bar
                    condition: selection
            """
                )
            )
        )
        == r"regexp(field, 'C:\\\\foo.*bar')"
    )


def test_base64_query(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|base64: 'sigma rules!'
                    condition: selection
            """
                )
            )
        )
        == "field ILIKE 'c2lnbWEgcnVsZXMh'"
    )


def test_condition_nested_logic(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel1:
                        field|contains:
                            - val1
                            - val2
                    sel2a:
                        field|endswith:
                            - val3
                    sel2b:
                        field|contains:
                            - val4
                    condition: sel1 or (sel2a and sel2b)
            """
                )
            )
        )
        == "(field ILIKE '%val1%' OR field ILIKE '%val2%') OR (field ILIKE '%val3' AND field ILIKE '%val4%')"
    )


def test_not_1_of_filter_condition(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|contains|all:
                            - val1
                            - val2
                    filter1:
                        field1|contains:
                            - val3
                    filter2:
                        field2|contains:
                            - val4
                    condition: selection and not 1 of filter*
            """
                )
            )
        )
        == "(field ILIKE '%val1%' AND field ILIKE '%val2%') AND (NOT (field1 ILIKE '%val3%' OR field2 ILIKE '%val4%'))"
    )


def test_multi_selection_same_field(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection1:
                        field1: 'test'
                        field2|contains|all:
                            - val1
                            - val2
                    selection2:
                        field2|contains|all:
                            - val3
                            - val4
                    selection3:
                        field2|contains|all:
                            - val5
                            - val6
                    condition: selection1 and (selection2 or selection3)
            """
                )
            )
        )
        == "(field1 ILIKE 'test' AND (field2 ILIKE '%val1%' AND field2 ILIKE '%val2%')) AND ((field2 ILIKE '%val3%' AND field2 ILIKE '%val4%') OR (field2 ILIKE '%val5%' AND field2 ILIKE '%val6%'))"
    )


def test_contains_wildcard(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: 'sigma %% rules!'
                    condition: selection
            """
                )
            )
        )
        == "field ILIKE 'sigma \\%\\% rules!'"
    )


def test_wildcards_and_backslash(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    r"""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: '*?%_\'
                    condition: selection
            """
                )
            )
        )
        == "field ILIKE '%_\\%\\_\\\\\\\\'"
    )


def test_condition_one_of_selection(backend: SparkSQLBackend):
    assert (
        single_rule_output_to_query(
            backend.convert(
                SigmaCollection.from_yaml(
                    """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection1:
                        Image|contains: '\\advanced_port_scanner'
                    selection2:
                        CommandLine|contains|all:
                            - '/portable'
                            - '/lng'
                    condition: 1 of selection*
            """
                )
            )
        )
        == "Image ILIKE '%\\\\\\\\advanced\\_port\\_scanner%' OR (CommandLine ILIKE '%/portable%' AND CommandLine ILIKE '%/lng%')"
    )


def test_simple_rule(backend: SparkSQLBackend):
    assert (
        (
            query := single_rule_output_to_query(
                backend.convert(
                    SigmaCollection.from_yaml(
                        r"""
            title: Rundll32 Execution Without DLL File
            id: c3a99af4-35a9-4668-879e-c09aeb4f2bdf
            status: experimental
            description: Detects the execution of rundll32 with a command line that doesn't contain a .dll file
            references:
                - https://twitter.com/mrd0x/status/1481630810495139841?s=12
            author: Tim Shelton, Florian Roth, Yassine Oukessou (fix + fp)
            date: 2022/01/13
            modified: 2023/01/25
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    ParentImage|endswith: '\conhost.exe'
                filter_provider:
                    Provider_Name: 'SystemTraceProvider-Process'
                filter_git:
                    Image|endswith: '\git.exe'
                    ParentCommandLine|contains: ' show '
                condition: selection and not 1 of filter_*
            fields:
                - Image
                - CommandLine
            falsepositives:
                - Unknown
            level: high
            """
                    )
                )
            )
        )
        == r"ParentImage ILIKE '%\\\\conhost.exe' AND (NOT (Provider_Name ILIKE 'SystemTraceProvider-Process' OR (Image ILIKE '%\\\\git.exe' AND ParentCommandLine ILIKE '% show %')))"
    ), query


def test_output_type(backend: SparkSQLBackend, rules: SigmaCollection):
    output = backend.convert(rules)

    assert isinstance(output, list)


def test_fetch_source_from_pipeline():
    pipeline = ProcessingPipeline(
        name="pipeline",
        items=[
            ProcessingItem(
                identifier="set_source_view",
                transformation=SetStateTransformation("source", {"view": "view", "table": "table"}),
                rule_conditions=[logsource_windows_process_creation()],
            ),
        ],
    )

    backend = SparkSQLBackend(processing_pipeline=pipeline)
    output = backend.convert(trivial_rule)
    assert len(output) == 1
    assert output[0] == ("SELECT * FROM table WHERE Foo ILIKE 'bar'")

    output = backend.convert(trivial_rule, source_type=SourceType.VIEW)
    assert len(output) == 1
    assert output[0] == ("SELECT * FROM view WHERE Foo ILIKE 'bar'")
