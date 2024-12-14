import builtins
import copy
import inspect
import io
import keyword
import os
import re
import sys
import tokenize
import traceback
import types
from pathlib import Path

import better_exceptions
import colorama
import loguru

colorama.init()
MAX_COLUMNS = 200
os.environ["COLUMNS"] = str(MAX_COLUMNS)


class Logger:
    levels = [
        {"name": "TRACE", "no": 5, "color": colorama.Fore.RESET},
        {"name": "DEBUG", "no": 10, "color": colorama.Fore.RESET},
        {"name": "VERBOSE", "no": 11, "color": colorama.Fore.LIGHTCYAN_EX},  # Added
        {"name": "INFO", "no": 20, "color": colorama.Fore.RESET},
        {"name": "NOTICE", "no": 21, "color": colorama.Fore.LIGHTBLUE_EX},  # Added
        {"name": "SUCCESS", "no": 25, "color": colorama.Fore.GREEN},
        {"name": "WARNING", "no": 30, "color": colorama.Fore.YELLOW},
        {"name": "ERROR", "no": 40, "color": colorama.Fore.RED},
        {"name": "CRITICAL", "no": 50, "color": colorama.Fore.RED},
    ]

    def __init__(self, src_logger = loguru.logger):
        self.level = "INFO"
        self.color = False
        for level in self.levels:  # Add new logging levels
            try:  # If log level already exists, the exception will be raised
                src_logger.level(name = level["name"], no = level["no"], color = level["color"])
            except Exception:
                src_logger.level(name = level["name"], color = level["color"])
        self.logger = src_logger

    def __getattr__(self, name):
        """Proxy all other logger methods"""
        return getattr(self.logger, name)

    def verbose(self, message, *args, **kwargs):
        self.logger.opt(depth = 1).log("VERBOSE", message, *args, **kwargs)

    def notice(self, message, *args, **kwargs):
        self.logger.opt(depth = 1).log("NOTICE", message, *args, **kwargs)

    def setup(self, log_file: str, verbose: bool, color: bool):
        """Method to set up the logger"""

        self.logger.remove()
        self.color = color
        if verbose:
            self.level = "VERBOSE"
        else:
            self.level = "INFO"

        preprocess_error_sink = {"sink": self.preprocess_error_sink, "level": "ERROR"}
        stdout_sink = {"sink": self.stdout_sink, "level": self.level}
        postprocess_error_sink = {"sink": self.postprocess_error_sink, "level": "ERROR"}

        config = {
            "handlers": [preprocess_error_sink, stdout_sink, postprocess_error_sink]
        }
        self.logger.configure(**config)

        if log_file:
            try:
                log_path = Path(log_file)
                log_path.parent.mkdir(parents = True, exist_ok = True)
                log_path.touch()
            except Exception as e:
                self.error(f"Unable to create log file '{log_file}': {e}")

            file_sink = {"sink": log_file, "level": self.level, "filter": self.file_filter, "format": "{formatted_message}", "mode": "w", "rotation": "10 MB"}
            config = {
                "handlers": [preprocess_error_sink, stdout_sink, file_sink, postprocess_error_sink]
            }
            self.logger.configure(**config)

    def preprocess_error_sink(self, message):
        # Get filename and line number where an error occurred
        msg = message.record["message"]
        filepath = message.record["file"].path
        line = message.record["line"]
        msg = f"{msg}\n\nFile: '{filepath}'\nLine: {line}"

        # Add traceback
        message.record["traceback"] = get_traceback(False, 6)
        message.record["colored_traceback"] = get_traceback(True, 6)
        message.record["message"] = msg
        return message

    def postprocess_error_sink(self, message):
        """Exit with code = line number"""
        line = message.record["line"]
        sys.exit(line)

    def stdout_sink(self, message):
        msg = message.record["message"]
        level = message.record["level"].name

        # Add prefix
        prefix = ""
        if level == "NOTICE":
            prefix = "[*] "
        elif level == "SUCCESS":
            prefix = "[+] "
        elif level == "WARNING":
            prefix = "[!] "
        elif level == "ERROR":
            prefix = "[-] "
        elif level == "CRITICAL":
            prefix = "[#] "
        msg = prefix + msg

        # Handle line updates using "\r"
        end = "\n"
        if msg.endswith("\r"):
            msg = msg[:-1]
            msg = "\r" + msg
            end = ""

        if self.color:
            color = self.logger.level(level).color
            msg = color + msg + colorama.Fore.RESET
        print(msg, end = end)

        # Add traceback
        if message.record["level"].no >= self.logger.level("ERROR").no:
            tb = message.record["traceback"]
            if self.color:
                tb = message.record["colored_traceback"]
            if self.level == "VERBOSE":
                print("\n" + tb)

    def parse_log_file(self, log_file: str) -> list:
        """Parse log file. Note that multiline messages will be truncated to 1st line"""
        try:
            pattern = re.compile(
                r"(?P<date>\d{4}-\d{2}-\d{2}) "
                r"(?P<time>\d{2}:\d{2}:\d{2}\.\d{3}) \| "
                r"(?P<level>\w+)\s*\| "
                r"(?P<file>[^:]+):"
                r"(?P<function>[^:]+):"
                r"(?P<line>\d+) \| "
                r"(?P<message>.*)"
            )
            entries = []
            for entry in self.logger.parse(log_file, pattern):
                entries.append(entry)
            return entries
        except Exception as e:
            self.error(f"Unable to parse '{log_file}': {e}")

    def file_filter(self, record):
        msg = record["message"]
        if msg.endswith("\r"):  # Ignore updatable line
            return False
        if not msg.strip():  # Ignore empty line
            return False

        if "traceback" in record.keys():
            msg += "\n\n" + record["traceback"]
        max_len_level = max(len(level["name"]) for level in self.levels)

        datetime = record["time"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        level = record["level"].name.ljust(max_len_level)
        source = record["file"].name + ":" + record["function"] + ":" + str(record["line"])

        msg = f"{datetime} | {level} | {source} | {msg}"
        record["formatted_message"] = msg
        return True


class SyntaxHighlighter:
    """Highlighter from loguru"""

    default_style = {
        "comment": colorama.Fore.LIGHTBLACK_EX + "{}" + colorama.Fore.RESET,
        "keyword": colorama.Fore.LIGHTMAGENTA_EX + "{}" + colorama.Fore.RESET,
        "builtin": "{}",
        "string": colorama.Fore.CYAN + "{}" + colorama.Fore.RESET,
        "number": colorama.Fore.LIGHTBLUE_EX + "{}" + colorama.Fore.RESET,
        "operator": colorama.Fore.LIGHTMAGENTA_EX + "{}" + colorama.Fore.RESET,
        "punctuation": "{}",
        "constant": colorama.Fore.CYAN + "{}" + colorama.Fore.RESET,
        "identifier": "{}",
        "other": "{}",
    }
    builtins = set(dir(builtins))
    constants = {"True", "False", "None"}
    punctuation = {"(", ")", "[", "]", "{", "}", ":", ",", ";"}
    strings = {tokenize.STRING}
    fstring_middle = None

    def __init__(self, style = None):
        if style:
            self.style = copy.deepcopy(style)  # Need to copy because dict is mutable
        else:
            self.style = copy.deepcopy(self.default_style)

    def highlight(self, source):
        style = self.style
        row, column = 0, 0
        output = ""

        for token in self.tokenize(source):
            type_, string, (start_row, start_column), (_, end_column), line = token

            if type_ == self.fstring_middle:
                # When an f-string contains "{{" or "}}", they appear as "{" or "}" in the "string"
                # attribute of the token. However, they do not count in the column position.
                end_column += string.count("{") + string.count("}")

            if type_ == tokenize.NAME:
                if string in self.constants:
                    color = style["constant"]
                elif keyword.iskeyword(string):
                    color = style["keyword"]
                elif string in self.builtins:
                    color = style["builtin"]
                else:
                    color = style["identifier"]
            elif type_ == tokenize.OP:
                if string in self.punctuation:
                    color = style["punctuation"]
                else:
                    color = style["operator"]
            elif type_ == tokenize.NUMBER:
                color = style["number"]
            elif type_ in self.strings:
                color = style["string"]
            elif type_ == tokenize.COMMENT:
                color = style["comment"]
            else:
                color = style["other"]

            if start_row != row:
                source = source[column:]
                row, column = start_row, 0

            if type_ != tokenize.ENCODING:
                output += line[column:start_column]
                output += color.format(line[start_column:end_column])
            column = end_column
        output += source[column:]
        return output

    @staticmethod
    def tokenize(source):
        source = source.encode("utf-8")
        source = io.BytesIO(source)
        try:
            yield from tokenize.tokenize(source.readline)
        except tokenize.TokenError:
            return


def display_default_colors():
    colors = {
        "black": [colorama.Fore.BLACK, colorama.Fore.LIGHTBLACK_EX],
        "red": [colorama.Fore.RED, colorama.Fore.LIGHTRED_EX],
        "green": [colorama.Fore.GREEN, colorama.Fore.LIGHTGREEN_EX],
        "yellow": [colorama.Fore.YELLOW, colorama.Fore.LIGHTYELLOW_EX],
        "blue": [colorama.Fore.BLUE, colorama.Fore.LIGHTBLUE_EX],
        "magenta": [colorama.Fore.MAGENTA, colorama.Fore.LIGHTMAGENTA_EX],
        "cyan": [colorama.Fore.CYAN, colorama.Fore.LIGHTCYAN_EX],
        "white": [colorama.Fore.WHITE, colorama.Fore.LIGHTWHITE_EX],
    }
    for color, prefixes in colors.items():
        s = prefixes[0] + color + "\t" + prefixes[1] + color
        print(s)


def convert_traceback(stack: traceback.StackSummary) -> types.TracebackType:
    tb = None
    prev_tb = None
    for frame_summary in reversed(stack):
        filename = frame_summary.filename
        lineno = frame_summary.lineno

        # Get the actual frame object
        frame = None
        for f in inspect.stack():
            if f.frame.f_code.co_filename == filename and f.frame.f_lineno == lineno:
                frame = f.frame
                break

        if frame:
            # Manually create a traceback object for each frame
            tb = types.TracebackType(
                tb_next = prev_tb,
                tb_frame = frame,
                tb_lasti = frame.f_lasti,
                tb_lineno = lineno
            )
            prev_tb = tb  # Set the previous traceback to chain it correctly
    return tb


def get_formatted_traceback(stack: traceback.StackSummary, color: bool, complex_theme = True, function_addr = False) -> str:
    source_highlighter = SyntaxHighlighter()
    val_highlighter = SyntaxHighlighter()
    for token_type in ["builtin", "identifier", "other"]:  # Threat tokens as strings
        val_highlighter.style[token_type] = val_highlighter.style["string"]

    pipe_char = "│"
    cap_char = "└"
    formatter = better_exceptions.ExceptionFormatter(colored = False, max_length = MAX_COLUMNS, pipe_char = pipe_char, cap_char = cap_char)

    # Convert stack summary to builtin traceback (linked list of frames)
    tb = convert_traceback(stack)
    frames = []
    while tb:
        frame, _ = formatter.format_traceback_frame(tb)
        frames.append(frame)
        tb = tb.tb_next

    tb_str = "Traceback (most recent call last):\n\n"
    if color:
        tb_str = colorama.Fore.YELLOW + tb_str + colorama.Fore.RESET

    # Format each frame
    for i, frame in enumerate(frames):
        filename, lineno, function, lines = frame
        lineno = str(lineno)
        lines = lines.split("\n")
        source = lines[0]
        vals = []
        if len(lines) > 1:  # 1st line = function prototype, 2d line = 1st arg val, 3rd line = 2nd arg val
            vals = lines[1:]

        # Remove function address
        if not function_addr and len(vals) > 0:
            vals = vals[:-1]
            vals = [val.replace(pipe_char, " ", 1) for val in vals]

        # Colorize frame
        if color:
            filename = colorama.Fore.GREEN + filename + colorama.Fore.RESET
            lineno = colorama.Fore.YELLOW + lineno + colorama.Fore.RESET
            function = colorama.Fore.LIGHTMAGENTA_EX + function + colorama.Fore.RESET

            source = source_highlighter.highlight(source)
            vals_color = []
            for val in vals:
                if complex_theme:
                    val = val_highlighter.highlight(val)
                else:
                    val = colorama.Fore.LIGHTCYAN_EX + val + colorama.Fore.RESET
                vals_color.append(val)
            vals = vals_color

        # Construct frame
        frm = "  "
        if i == len(frames) - 1:
            frm = "> "  # Mark last frame
        frm += f'File "{filename}", line {lineno}, in {function}\n'
        frm += f"    {source}\n"
        for val in vals:
            frm += val + "\n"
        tb_str += frm + "\n"
    return tb_str.strip()


def get_traceback(color: bool, depth = 1, complex_theme = True) -> str:
    raw_stack = traceback.extract_stack()
    if len(raw_stack) > depth:  # Ignore too deep frames
        raw_stack = raw_stack[:-depth]

    # Ignore modules loaded when app runs as module or .exe (not as script)
    stack = []
    for frame in raw_stack:
        filename = frame.filename
        if not ("runpy" in filename or "cx_Freeze" in filename):
            stack.append(frame)
    stack = traceback.StackSummary(stack)

    try:
        tb = get_formatted_traceback(stack, color, complex_theme)
    except Exception:
        # If unable to format traceback, use very simple one
        tbl = traceback.format_list(stack)
        tb = "Cannot display pretty formatted traceback :(\n\n"
        tb += "Traceback (most recent call last):\n" + "".join(tbl).strip()
        if color:
            tb = colorama.Fore.RED + tb + colorama.Fore.RESET
    return tb


logger = Logger()
