"""Helpers for shell commands embedded in source-code call sites."""
from __future__ import annotations

import ast
from dataclasses import dataclass
import re
import warnings

from github_inventory.discovery import FileTarget


@dataclass(frozen=True)
class SourceShellCommand:
    line_number: int
    command: str
    matched_text: str
    origin: str = "literal"


_SUBPROCESS_CALLS = {"run", "call", "check_call", "check_output", "Popen"}
_JAVASCRIPT_SHELL_CALLS = {
    "exec",
    "execSync",
    "executeInTerminal",
    "execFile",
    "execFileSync",
    "execa",
    "runStreamedCommand",
    "sendText",
    "spawn",
    "spawnSync",
}
_JAVASCRIPT_COMMAND_BUILDER_CALLS = {
    "getUvPathCommand",
}


def parse_python_source(content: str) -> ast.Module:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(content)


def iter_python_shell_commands(
    target: FileTarget,
    content: str,
    lines: list[str],
) -> list[SourceShellCommand]:
    if (
        target.file_type != "source_code"
        or target.path.suffix.lower() != ".py"
        or _is_test_source_path(target.rel_path)
    ):
        return []
    try:
        tree = parse_python_source(content)
    except SyntaxError:
        return []

    commands: list[SourceShellCommand] = []
    string_constants = _python_literal_string_assignments(tree)
    assigned_commands = _python_string_assignments(tree, lines, string_constants)
    assigned_command_lists = _python_string_list_assignments(tree, lines, string_constants)
    assigned_argv_commands = _python_shell_argv_assignments(
        tree,
        assigned_commands,
        string_constants,
        lines,
    )
    commands.extend(_python_loop_shell_commands(tree, assigned_command_lists, lines))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        origin = "literal"
        if _is_os_system_call(node.func) or _is_subprocess_shell_call(node):
            command = _literal_command_text(node.args[0], string_constants)
        elif _is_subprocess_call(node.func):
            command_sources = _python_subprocess_command_sources(
                node,
                assigned_commands,
                assigned_argv_commands,
                string_constants,
                lines,
            )
            commands.extend(command_sources)
            continue
        elif _is_os_exec_call(node.func):
            commands.extend(
                _python_os_exec_command_sources(
                    node,
                    assigned_commands,
                    assigned_argv_commands,
                    string_constants,
                    lines,
                )
            )
            continue
        elif _is_python_command_wrapper_call(node.func):
            commands.extend(_python_wrapper_command_sources(
                node,
                assigned_commands,
                string_constants,
                lines,
            ))
            continue
        else:
            continue
        if not command:
            continue
        line_number = getattr(node, "lineno", 1)
        source_line = lines[line_number - 1] if 0 < line_number <= len(lines) else command
        commands.append(SourceShellCommand(
            line_number=line_number,
            command=command,
            matched_text=source_line.strip()[:200],
            origin=origin,
        ))
    return commands


def _python_string_list_assignments(
    tree: ast.AST,
    lines: list[str],
    constants: dict[str, str],
) -> dict[str, list[SourceShellCommand]]:
    assigned: dict[str, list[SourceShellCommand]] = {}
    for node in ast.walk(tree):
        value: ast.expr | None = None
        names: list[str] = []
        if isinstance(node, ast.Assign):
            value = node.value
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            value = node.value
            names = [node.target.id]
        if value is None or not names or not isinstance(value, (ast.List, ast.Tuple)):
            continue
        commands = [
            _python_source_shell_command(element, command, lines)
            for element in value.elts
            if (command := _literal_command_text(element, constants))
        ]
        if not commands:
            continue
        for name in names:
            assigned[name] = commands
    return assigned


def _python_shell_argv_assignments(
    tree: ast.AST,
    assigned_commands: dict[str, list[SourceShellCommand]],
    constants: dict[str, str],
    lines: list[str],
) -> dict[str, list[SourceShellCommand]]:
    assigned: dict[str, list[SourceShellCommand]] = {}
    for node in ast.walk(tree):
        value: ast.expr | None = None
        names: list[str] = []
        if isinstance(node, ast.Assign):
            value = node.value
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            value = node.value
            names = [node.target.id]
        if value is None or not names or not isinstance(value, (ast.List, ast.Tuple)):
            continue
        commands = _python_argv_embedded_shell_commands(value, assigned_commands, constants, lines)
        if not commands:
            continue
        for name in names:
            assigned[name] = commands
    return assigned


def _python_loop_shell_commands(
    tree: ast.AST,
    assigned_command_lists: dict[str, list[SourceShellCommand]],
    lines: list[str],
) -> list[SourceShellCommand]:
    commands: list[SourceShellCommand] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.For) or not isinstance(node.target, ast.Name):
            continue
        if not isinstance(node.iter, ast.Name):
            continue
        list_commands = assigned_command_lists.get(node.iter.id)
        if not list_commands:
            continue
        if _python_loop_executes_command_var(node, node.target.id):
            commands.extend(list_commands)
    return commands


def _python_loop_executes_command_var(node: ast.For, loop_var: str) -> bool:
    aliases = {loop_var}
    for child in ast.walk(node):
        if isinstance(child, ast.Assign):
            if _python_expr_references_name(child.value, aliases):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        aliases.add(target.id)
        elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
            if child.value is not None and _python_expr_references_name(child.value, aliases):
                aliases.add(child.target.id)
        elif isinstance(child, ast.Call) and _is_python_shell_wrapper_call(child.func):
            if _python_call_uses_alias(child, aliases):
                return True
    return False


def _python_expr_references_name(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


def _python_call_uses_alias(node: ast.Call, aliases: set[str]) -> bool:
    return any(_python_expr_references_name(arg, aliases) for arg in node.args) or any(
        keyword.value is not None and _python_expr_references_name(keyword.value, aliases)
        for keyword in node.keywords
    )


def _is_python_shell_wrapper_call(func: ast.expr) -> bool:
    if isinstance(func, ast.Name):
        return func.id in {"docker_exec", "exec_command", "execute_command", "run_command"}
    return isinstance(func, ast.Attribute) and func.attr in {"execute", "exec", "run_command", "_call"}


def _python_literal_string_assignments(tree: ast.AST) -> dict[str, str]:
    assigned: dict[str, str] = {}
    for node in ast.walk(tree):
        value: ast.expr | None = None
        names: list[str] = []
        if isinstance(node, ast.Assign):
            value = node.value
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            value = node.value
            names = [node.target.id]
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        for name in names:
            assigned[name] = value.value
    return assigned


def _python_string_assignments(
    tree: ast.AST,
    lines: list[str],
    constants: dict[str, str],
) -> dict[str, list[SourceShellCommand]]:
    assigned: dict[str, list[SourceShellCommand]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            command = _literal_command_text(node.value, constants)
            if not command:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned.setdefault(target.id, []).append(_python_source_shell_command(node, command, lines))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            command = _literal_command_text(node.value, constants) if node.value is not None else ""
            if command:
                assigned.setdefault(node.target.id, []).append(_python_source_shell_command(node, command, lines))
    return assigned


def _python_source_shell_command(
    node: ast.AST,
    command: str,
    lines: list[str],
    *,
    origin: str = "literal",
) -> SourceShellCommand:
    line_number = getattr(node, "lineno", 1)
    source_line = lines[line_number - 1] if 0 < line_number <= len(lines) else command
    return SourceShellCommand(
        line_number=line_number,
        command=command,
        matched_text=source_line.strip()[:200],
        origin=origin,
    )


def _is_python_command_wrapper_call(func: ast.expr) -> bool:
    return _is_python_shell_wrapper_call(func) or _is_python_run_cmd_call(func)


def _is_python_run_cmd_call(func: ast.expr) -> bool:
    if isinstance(func, ast.Name):
        return func.id == "RunCmd"
    return isinstance(func, ast.Attribute) and func.attr == "RunCmd"


def _python_wrapper_command_sources(
    node: ast.Call,
    assigned_commands: dict[str, list[SourceShellCommand]],
    constants: dict[str, str],
    lines: list[str],
) -> list[SourceShellCommand]:
    argv_command = _python_wrapper_argv_command_text(node, constants)
    if argv_command:
        return [_python_source_shell_command(node, argv_command, lines, origin="argv")]

    commands: list[SourceShellCommand] = []
    for arg in node.args:
        commands.extend(_python_command_sources_from_arg(arg, node, assigned_commands, constants, lines))
    for keyword in node.keywords:
        if keyword.arg == "command":
            commands.extend(_python_command_sources_from_value(
                keyword.value,
                node,
                assigned_commands,
                constants,
                lines,
            ))
    return commands


def _python_wrapper_argv_command_text(node: ast.Call, constants: dict[str, str]) -> str:
    if not _is_python_run_cmd_call(node.func) or not node.args:
        return ""
    executable = _python_argv_token(node.args[0], constants)
    if executable not in {"curl", "wget", "gh", "aria2", "aria2c"}:
        return ""
    tokens = [executable]
    for arg in node.args[1:]:
        token = _python_argv_token(arg, constants)
        if token:
            tokens.append(token)
    return " ".join(tokens) if len(tokens) >= 2 else ""


def _python_command_sources_from_arg(
    arg: ast.expr,
    call_node: ast.Call,
    assigned_commands: dict[str, list[SourceShellCommand]],
    constants: dict[str, str],
    lines: list[str],
) -> list[SourceShellCommand]:
    if isinstance(arg, ast.Dict):
        commands: list[SourceShellCommand] = []
        for key, value in zip(arg.keys, arg.values):
            if isinstance(key, ast.Constant) and key.value == "command":
                commands.extend(_python_command_sources_from_value(
                    value,
                    call_node,
                    assigned_commands,
                    constants,
                    lines,
                ))
        return commands
    return _python_command_sources_from_value(arg, call_node, assigned_commands, constants, lines)


def _python_command_sources_from_value(
    value: ast.expr,
    call_node: ast.AST,
    assigned_commands: dict[str, list[SourceShellCommand]],
    constants: dict[str, str],
    lines: list[str],
) -> list[SourceShellCommand]:
    command = _literal_command_text(value, constants)
    if command:
        return [_python_source_shell_command(call_node, command, lines)]
    if isinstance(value, (ast.List, ast.Tuple)):
        embedded = _python_argv_embedded_shell_commands(value, assigned_commands, constants, lines)
        if embedded:
            return embedded
        argv_command = _python_argv_command_text(value, constants)
        if argv_command:
            return [_python_source_shell_command(call_node, argv_command, lines, origin="argv")]
    if isinstance(value, ast.Name):
        return assigned_commands.get(value.id, [])
    return []


def iter_javascript_shell_commands(
    target: FileTarget,
    content: str,
    lines: list[str],
) -> list[SourceShellCommand]:
    if (
        target.file_type != "source_code"
        or not _is_js_source_path(target.rel_path)
        or _is_test_source_path(target.rel_path)
    ):
        return []

    commands: list[SourceShellCommand] = []
    assigned_commands: dict[str, list[SourceShellCommand]] = {}
    pending_assignment = ""
    pending_builder_assignment = ""
    for line_number, line in enumerate(lines, start=1):
        if pending_assignment:
            command = _js_call_first_string_literal(line, 0)
            if command:
                assigned_commands.setdefault(pending_assignment, []).append(SourceShellCommand(
                    line_number=line_number,
                    command=command,
                    matched_text=line.strip()[:200],
                ))
                pending_assignment = ""
            elif line.strip() and not line.lstrip().startswith("//"):
                pending_assignment = ""

        if pending_builder_assignment:
            command = _js_call_first_string_literal(line, 0)
            if command:
                assigned_commands.setdefault(pending_builder_assignment, []).append(SourceShellCommand(
                    line_number=line_number,
                    command=command,
                    matched_text=line.strip()[:200],
                ))
                pending_builder_assignment = ""
            elif line.strip() and not line.lstrip().startswith("//"):
                pending_builder_assignment = ""

        assignment = _js_string_assignment(line, line_number)
        if assignment is not None:
            name, command = assignment
            assigned_commands.setdefault(name, []).append(command)
        else:
            builder_assignment = _js_command_builder_assignment(line, line_number)
            if builder_assignment is not None:
                name, command = builder_assignment
                assigned_commands.setdefault(name, []).append(command)
            else:
                pending_assignment = _js_pending_string_assignment_name(line)
                pending_builder_assignment = _js_pending_command_builder_assignment_name(line)

        for match in re.finditer(r"\b(?P<name>[A-Za-z_$][\w$]*)\s*\(", line):
            if match.group("name") not in _JAVASCRIPT_SHELL_CALLS:
                continue
            argv_command = _js_argv_call_command(line, match.end())
            if argv_command:
                commands.append(SourceShellCommand(
                    line_number=line_number,
                    command=argv_command,
                    matched_text=line.strip()[:200],
                    origin="argv",
                ))
                continue
            command = _js_call_first_string_literal(line, match.end())
            if not command:
                command = _js_multiline_call_first_string_literal(lines, line_number - 1, match.end())
            if command:
                commands.append(SourceShellCommand(
                    line_number=line_number,
                    command=command,
                    matched_text=line.strip()[:200],
                ))
                continue
            identifier = _js_call_first_identifier(line, match.end())
            if identifier:
                commands.extend(assigned_commands.get(identifier, []))
    return commands


def _is_subprocess_shell_call(node: ast.Call) -> bool:
    func = node.func
    if not _is_subprocess_call(func):
        return False
    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    )


def _is_subprocess_call(func: ast.expr) -> bool:
    return (
        isinstance(func, ast.Attribute)
        and func.attr in _SUBPROCESS_CALLS
        and isinstance(func.value, ast.Name)
        and func.value.id == "subprocess"
    )


def _is_os_exec_call(func: ast.expr) -> bool:
    return (
        isinstance(func, ast.Attribute)
        and func.attr in {"execv", "execve", "execvp", "execvpe"}
        and isinstance(func.value, ast.Name)
        and func.value.id == "os"
    )


def _is_os_system_call(func: ast.expr) -> bool:
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "system"
        and isinstance(func.value, ast.Name)
        and func.value.id == "os"
    )


def _literal_command_text(node: ast.expr, constants: dict[str, str] | None = None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                parts.append(_python_formatted_value_text(value.value, constants))
        return "".join(parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"strip", "lstrip", "rstrip"}
        and not node.args
        and not node.keywords
    ):
        command = _literal_command_text(node.func.value, constants)
        if node.func.attr == "strip":
            return command.strip()
        if node.func.attr == "lstrip":
            return command.lstrip()
        return command.rstrip()
    return ""


def _python_formatted_value_text(node: ast.expr, constants: dict[str, str] | None) -> str:
    constant = _python_constant_text(node, constants)
    if constant:
        return constant
    if isinstance(node, ast.Name):
        return f"${node.id}"
    return "${...}"


def _python_constant_text(node: ast.expr, constants: dict[str, str] | None) -> str:
    if not constants:
        return ""
    if isinstance(node, ast.Name):
        return constants.get(node.id, "")
    return ""


def _python_subprocess_command_sources(
    node: ast.Call,
    assigned_commands: dict[str, list[SourceShellCommand]],
    assigned_argv_commands: dict[str, list[SourceShellCommand]],
    constants: dict[str, str],
    lines: list[str],
) -> list[SourceShellCommand]:
    arg = node.args[0]
    command = _python_split_command_text(arg, constants)
    if command:
        return [_python_source_shell_command(node, command, lines, origin="argv")]
    if isinstance(arg, ast.Name):
        commands = assigned_argv_commands.get(arg.id, [])
        if commands:
            return commands
    if isinstance(arg, (ast.List, ast.Tuple)):
        commands = _python_argv_embedded_shell_commands(arg, assigned_commands, constants, lines)
        if commands:
            return commands
        command = _python_argv_command_text(arg, constants)
        if command:
            return [_python_source_shell_command(node, command, lines, origin="argv")]
    return []


def _python_split_command_text(node: ast.expr, constants: dict[str, str]) -> str:
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "split"
        and not node.args
        and not node.keywords
    ):
        return _literal_command_text(node.func.value, constants)
    return ""


def _python_os_exec_command_sources(
    node: ast.Call,
    assigned_commands: dict[str, list[SourceShellCommand]],
    assigned_argv_commands: dict[str, list[SourceShellCommand]],
    constants: dict[str, str],
    lines: list[str],
) -> list[SourceShellCommand]:
    if len(node.args) < 2:
        return []
    argv = node.args[1]
    if isinstance(argv, ast.Name):
        return assigned_argv_commands.get(argv.id, [])
    if isinstance(argv, (ast.List, ast.Tuple)):
        return _python_argv_embedded_shell_commands(argv, assigned_commands, constants, lines)
    return []


def _python_argv_embedded_shell_commands(
    node: ast.List | ast.Tuple,
    assigned_commands: dict[str, list[SourceShellCommand]],
    constants: dict[str, str],
    lines: list[str],
) -> list[SourceShellCommand]:
    if not node.elts:
        return []
    executable = _python_argv_token(node.elts[0], constants).lower()
    shell_flags: set[str]
    if executable in {"sh", "bash", "zsh", "dash"}:
        shell_flags = {"-c"}
    elif executable in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        shell_flags = {"-c", "-command", "/c"}
    else:
        return []
    for index, element in enumerate(node.elts[:-1]):
        token = _python_argv_token(element, constants).lower()
        if token in shell_flags:
            return _python_command_sources_from_value(
                node.elts[index + 1],
                node,
                assigned_commands,
                constants,
                lines,
            )
    return []


def _python_argv_command_text(node: ast.expr, constants: dict[str, str] | None = None) -> str:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return ""
    tokens: list[str] = []
    for element in node.elts:
        token = _python_argv_token(element, constants)
        if token:
            tokens.append(token)
    if len(tokens) >= 4 and tokens[0] == "python" and tokens[1] == "-m" and tokens[2] in {"pip", "pip3"}:
        return " ".join(tokens)
    if len(tokens) >= 2 and tokens[0] in {"pip", "pip3", "npm", "brew", "winget"}:
        return " ".join(tokens)
    if len(tokens) >= 2 and tokens[0] in {"curl", "wget", "gh", "aria2", "aria2c"}:
        return " ".join(tokens)
    if len(tokens) >= 3 and tokens[0] in {"az", "az.cmd", "az.exe"}:
        return " ".join(tokens)
    return ""


def _python_argv_token(node: ast.expr, constants: dict[str, str] | None = None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return _literal_command_text(node, constants)
    if isinstance(node, ast.Name):
        constant = _python_constant_text(node, constants)
        if constant:
            return constant
        return f"${node.id}"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _python_argv_token(node.left, constants)
        right = _python_argv_token(node.right, constants)
        if left.startswith("$") and right.startswith("$"):
            right = "${" + right[1:] + "}"
        return left + right if left and right else left or right
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "executable"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    ):
        return "python"
    return ""


def _js_call_first_string_literal(line: str, index: int) -> str:
    while index < len(line) and line[index].isspace():
        index += 1
    parsed = _js_string_literal_at(line, index)
    return parsed[0] if parsed else ""


def _js_multiline_call_first_string_literal(lines: list[str], start_line: int, index: int) -> str:
    parts = [lines[start_line][index:]]
    for line in lines[start_line + 1:start_line + 25]:
        parts.append(line)
        args = _js_call_arguments("\n".join(parts), 0)
        if not args:
            continue
        return _js_concatenated_string_literal_text(args[0])
    return ""


def _js_concatenated_string_literal_text(expr: str) -> str:
    index = 0
    values: list[str] = []
    saw_value = False
    expect_value = True
    while index < len(expr):
        while index < len(expr) and expr[index].isspace():
            index += 1
        if index >= len(expr):
            break
        if expect_value:
            parsed = _js_string_literal_at(expr, index)
            if not parsed:
                return ""
            value, index = parsed
            values.append(value)
            saw_value = True
            expect_value = False
            continue
        if expr[index] != "+":
            return ""
        index += 1
        expect_value = True
    return "".join(values) if saw_value and not expect_value else ""


def _js_string_literal_at(line: str, index: int) -> tuple[str, int] | None:
    if index >= len(line) or line[index] not in {"'", '"', "`"}:
        return None
    quote = line[index]
    index += 1
    chars: list[str] = []
    escaped = False
    while index < len(line):
        char = line[index]
        if escaped:
            chars.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if char == quote:
            return "".join(chars), index + 1
        chars.append(char)
        index += 1
    return None


def _js_string_assignment(line: str, line_number: int) -> tuple[str, SourceShellCommand] | None:
    match = _js_assignment_match(line)
    if not match:
        return None
    command = _js_call_first_string_literal(line, match.end())
    if not command:
        return None
    return match.group("name"), SourceShellCommand(
        line_number=line_number,
        command=command,
        matched_text=line.strip()[:200],
    )


def _js_pending_string_assignment_name(line: str) -> str:
    match = _js_assignment_match(line)
    if not match:
        return ""
    suffix = line[match.end():].strip()
    return match.group("name") if suffix in {"", "("} else ""


def _js_command_builder_assignment(line: str, line_number: int) -> tuple[str, SourceShellCommand] | None:
    match = _js_command_builder_assignment_match(line)
    if not match:
        return None
    command = _js_call_first_string_literal(line, match.end())
    if not command:
        return None
    return match.group("name"), SourceShellCommand(
        line_number=line_number,
        command=command,
        matched_text=line.strip()[:200],
    )


def _js_pending_command_builder_assignment_name(line: str) -> str:
    match = _js_command_builder_assignment_match(line)
    if not match:
        return ""
    suffix = line[match.end():].strip()
    return match.group("name") if suffix in {"", "("} else ""


def _js_command_builder_assignment_match(line: str) -> re.Match[str] | None:
    assignment = _js_assignment_match(line)
    if not assignment:
        return None
    match = re.match(r"(?P<builder>[A-Za-z_$][\w$]*)\s*\(", line[assignment.end():])
    if not match or match.group("builder") not in _JAVASCRIPT_COMMAND_BUILDER_CALLS:
        return None
    return re.search(
        r"\b(?:(?:const|let|var)\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*"
        + re.escape(match.group("builder"))
        + r"\s*\(",
        line,
    )


def _js_assignment_match(line: str) -> re.Match[str] | None:
    return re.search(
        r"\b(?:(?:const|let|var)\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*",
        line,
    )


def _js_call_first_identifier(line: str, index: int) -> str:
    while index < len(line) and line[index].isspace():
        index += 1
    match = re.match(r"[A-Za-z_$][\w$]*", line[index:])
    return match.group(0) if match else ""


def _js_argv_call_command(line: str, index: int) -> str:
    args = _js_call_arguments(line, index)
    if len(args) < 2:
        return ""
    executable = _js_command_name(args[0])
    strings = _js_string_literals(args[1])
    if not strings:
        return ""
    if executable in {"bash", "sh", "zsh", "dash"}:
        return _js_shell_c_command(strings)
    if executable in {"curl", "wget", "gh", "aria2", "aria2c"}:
        tokens = _js_argv_tokens(args[1])
        return executable + " " + " ".join(tokens) if tokens else ""
    if executable not in {"npm", "brew", "winget"}:
        return ""
    install_words = {"install", "i"} if executable == "npm" else {"install"}
    while strings and strings[0] not in install_words:
        strings.pop(0)
    if not strings:
        return ""
    return executable + " " + " ".join(strings)


def _js_shell_c_command(strings: list[str]) -> str:
    for index, token in enumerate(strings):
        if token == "-c" and index + 1 < len(strings):
            return strings[index + 1]
    return ""


def _js_call_arguments(line: str, index: int) -> list[str]:
    depth = 1
    quote = ""
    escaped = False
    current: list[str] = []
    args: list[str] = []
    while index < len(line):
        char = line[index]
        if quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            current.append(char)
            index += 1
            continue
        if char in "([{":
            depth += 1
            current.append(char)
            index += 1
            continue
        if char in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(current).strip())
                return args
            current.append(char)
            index += 1
            continue
        if char == "," and depth == 1:
            args.append("".join(current).strip())
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    return []


def _js_command_name(expr: str) -> str:
    stripped = expr.strip()
    literal = _js_call_first_string_literal(stripped, 0)
    if literal:
        return literal.lower()
    lowered = stripped.lower()
    for command in ("npm", "brew", "winget", "bash", "sh", "zsh", "dash", "curl", "wget", "gh", "aria2", "aria2c"):
        if command in lowered:
            return command
    return ""


def _js_argv_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char in {"'", '"'}:
            parsed = _js_string_literal_at(text, index)
            if parsed and not text[:index].rstrip().endswith("..."):
                value, index = parsed
                tokens.append(value)
            else:
                index += 1
            continue
        if char == "`":
            parsed = _js_string_literal_at(text, index)
            if parsed and not text[:index].rstrip().endswith("..."):
                value, index = parsed
                tokens.append(value)
            else:
                index += 1
            continue
        if re.match(r"[A-Za-z_$]", char):
            match = re.match(r"[A-Za-z_$][\w$]*", text[index:])
            if match:
                name = match.group(0)
                if name not in {"true", "false", "null", "undefined"} and not text[:index].rstrip().endswith("..."):
                    tokens.append(f"${name}")
                index += len(name)
                continue
        index += 1
    return tokens


def _js_string_literals(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"""(?P<quote>['"])(?P<value>(?:\\.|(?!\1).)*?)(?P=quote)""", text):
        if text[:match.start()].rstrip().endswith("..."):
            continue
        values.append(match.group("value"))
    return values


def _is_js_source_path(rel_path: str) -> bool:
    return rel_path.replace("\\", "/").lower().endswith(
        (".js", ".mjs", ".cjs", ".ts", ".mts", ".jsx", ".tsx")
    )


def _is_test_source_path(rel_path: str) -> bool:
    rel_norm = rel_path.replace("\\", "/")
    rel_lower = rel_norm.lower()
    path = f"/{rel_lower}"
    if any(segment in path for segment in (
        "/test/",
        "/tests/",
        "/testing/",
        "/testdata/",
        "/unittest/",
        "/unittests/",
    )):
        return True
    name = rel_lower.rsplit("/", 1)[-1]
    original_name = rel_norm.rsplit("/", 1)[-1]
    return (
        name.startswith("test_")
        or bool(re.match(r"^(?:test|Test)(?:[-_.A-Z0-9]).*\.(?:[cm]?[jt]sx?|py)$", original_name))
        or name.endswith("_test.py")
        or name.endswith(".test.ts")
        or ".spec." in name
    )
