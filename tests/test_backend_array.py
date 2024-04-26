from sigma.backends.spark import ArraySparkSQLBackend
from sigma.collection import SigmaCollection


def single_rule_output_to_map_key(output: str) -> str:
    return (
        output.removeprefix(
            """\
SELECT
    *,
    map_keys(
    map_filter(
    map(
"""
        )
        .split("\n")[0]
        .strip()
        .removesuffix(",")
    )


def single_rule_output_to_query(output: str) -> str:
    return (
        output.removeprefix(
            """\
SELECT
    *,
    map_keys(
    map_filter(
    map(
"""
        )
        .split("\n")[1]
        .strip()[1:-1]
    )


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


def test_rule_name_escaping(array: ArraySparkSQLBackend):
    rule = SigmaCollection.from_yaml(
        """\
title: Test*?%_'\\
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Foo: bar
    condition: selection"""
    )
    assert single_rule_output_to_map_key(array.convert(rule)) == "'Test*?%_\\'\\\\'"


def test_output_to_query(array: ArraySparkSQLBackend):
    output = array.convert(trivial_rule)
    assert (
        output
        == """\
SELECT
    *,
    map_keys(
    map_filter(
    map(
        'Test',
        (Foo ILIKE 'bar')
    )
    , (k,v) -> v = TRUE)) as sigma_final
FROM
    --SOURCE
"""
    )
    assert single_rule_output_to_query(output) == "Foo ILIKE 'bar'"


def test_convert_basic(array: ArraySparkSQLBackend, rules: SigmaCollection):
    output = array.convert(rules)

    assert type(output) is str


def test_single_quote(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_triple_quote(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_leql_detection_definition_output_format(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_not_condition_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_simple_contains_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_simple_startswith_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_simple_endswith_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_value_in_list_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_value_eq_or_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_keyword_or_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_keyword_and_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_value_eq_and_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_contains_any_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_contains_all_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_startswith_any_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_endswith_any_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_re_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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
        # == "re.search(re.compile(br'boo.*far'),field)"
        == "regexp(field, 'boo.*far')"
    )


def test_re_query_with_backslashes(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_base64_query(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_condition_nested_logic(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_not_1_of_filter_condition(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_multi_selection_same_field(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_contains_wildcard(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_wildcards_and_backslash(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_condition_one_of_selection(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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


def test_simple_rule(array: ArraySparkSQLBackend):
    assert (
        single_rule_output_to_query(
            array.convert(
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
        == r"ParentImage ILIKE '%\\\\conhost.exe' AND (NOT (Provider_Name ILIKE 'SystemTraceProvider-Process' OR (Image ILIKE '%\\\\git.exe' AND ParentCommandLine ILIKE '% show %')))"
    )
