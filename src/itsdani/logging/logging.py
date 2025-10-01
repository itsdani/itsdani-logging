import json
import logging
import os
import re
import traceback
from collections.abc import Mapping
from datetime import datetime, timezone
from types import TracebackType
from typing import Any, Literal, TypeAlias, override

ExcInfo: TypeAlias = tuple[
    type[BaseException],
    BaseException,
    TracebackType | None,
]
OptExcInfo: TypeAlias = ExcInfo | tuple[None, None, None]
ArgsType: TypeAlias = tuple[object, ...] | Mapping[str, object]


def get_formatted_stack_trace(exc_info: OptExcInfo) -> str:
    STACK_TRACE_LIMIT = 3000
    formatted_stack_trace = traceback.format_exception(
        *exc_info,
        limit=STACK_TRACE_LIMIT,
    )
    return "".join(f"\t{trace_line}" for trace_line in formatted_stack_trace)


class ExtraLogger(logging.Logger):
    """Custom logger that adds extra fields to log records.

    This logger adds the "extra" field instead of spreading its content to the
    root level of the log record.
    """

    @override
    def makeRecord(
        self,
        name: str,
        level: int,
        fn: str,
        lno: int,
        msg: object,
        args: ArgsType,
        exc_info: OptExcInfo | None = None,
        func: str | None = None,
        extra: Mapping[str, object] | None = None,
        sinfo: str | None = None,
    ):
        log_record = super().makeRecord(
            name=name,
            level=level,
            fn=fn,
            lno=lno,
            msg=msg,
            args=args,
            exc_info=exc_info,
            func=func,
            extra=extra,
            sinfo=sinfo,
        )
        log_record.extra = extra
        return log_record


class ColoredExtraConsoleLogFormatter(logging.Formatter):
    """Console formatter with readable colored output, rendering extra fields and exception stack-traces."""

    def __init__(self):
        super().__init__()

    @override
    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.now(timezone.utc).time().strftime("%H:%M:%S")

        # ANSI escape codes for colored output
        RED = "\033[91m"
        ORANGE = "\033[33m"
        GREEN = "\033[32m"
        CYAN = "\033[36m"
        RESET = "\033[0m"

        log_level = record.levelname if hasattr(record, "levelname") else None
        project_name = record.name if hasattr(record, "name") else None
        message = record.getMessage()

        formatted_extra = (
            "".join([f"\n\t{key}: {value}" for key, value in record.extra.items()])  # type: ignore
            if hasattr(record, "extra") and isinstance(record.extra, dict)  # type: ignore
            else ""
        )

        formatted_stack_trace = (
            f"{RED}\n{get_formatted_stack_trace(exc_info=record.exc_info)}{RESET}"
            if hasattr(record, "exc_info") and isinstance(record.exc_info, tuple)
            else ""
        )

        if log_level in ["ERROR", "CRITICAL", "FATAL"]:
            log_level = f"{RED}{log_level}{RESET}"
        if log_level in ["WARNING", "WARN"]:
            log_level = f"{ORANGE}{log_level}{RESET}"
        if log_level in ["INFO"]:
            log_level = f"{GREEN}{log_level}{RESET}"
        if log_level in ["DEBUG", "TRACE"]:
            log_level = f"{CYAN}{log_level}{RESET}"

        formatted_log = f"[{timestamp}] [{log_level}] [{project_name}] {message}"
        formatted_log += formatted_extra
        formatted_log += formatted_stack_trace

        return formatted_log


def _get_module_name(path_name: str) -> str:
    return os.path.splitext(os.path.basename(path_name))[0]


def _normalize_extra(extra: dict[str, Any]) -> dict[str, str | int | float]:
    normalized_pairs: list[tuple[str, str | int | float]] = []
    for key, value in extra.items():
        if isinstance(value, int) or isinstance(value, float):
            normalized_pairs.append((key, value))
        else:
            normalized_pairs.append((key, str(value)))
    return dict(normalized_pairs)


def _get_timestamp():
    DATETIME_FORMAT_WITH_TIMEZONE = "%Y-%m-%dT%H:%M:%S%z"
    now_in_utc = datetime.now(timezone.utc)
    return now_in_utc.strftime(DATETIME_FORMAT_WITH_TIMEZONE)


class ExtraLogJsonFormatter(logging.Formatter):
    """JSON formatter that adds extra fields and exception stack-traces to the log record."""

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        style: Literal["%"] | Literal["{"] | Literal["$"] = "%",
    ):
        super(ExtraLogJsonFormatter, self).__init__()

    @override
    def format(self, record: logging.LogRecord) -> str:
        module_name = (
            _get_module_name(path_name=record.pathname)
            if hasattr(record, "pathname")
            else None
        )

        stack_trace: str | None = (
            get_formatted_stack_trace(exc_info=record.exc_info)
            if hasattr(record, "exc_info") and isinstance(record.exc_info, tuple)
            else None
        )

        message = record.getMessage()

        extra = (
            _normalize_extra(extra=record.extra)
            if hasattr(record, "extra") and isinstance(record.extra, dict)
            else None
        )

        line_number = str(record.lineno) if hasattr(record, "lineno") else None

        data = {
            "timestamp": _get_timestamp(),
            "loglevel": getattr(record, "levelname", None),
            "projectName": getattr(record, "name", None),
            "moduleName": module_name,
            "pathName": getattr(record, "pathname", None),
            "lineNumber": line_number,
            "stackTrace": stack_trace,
            "message": message,
            "processId": str(os.getpid()),
            "extra": extra,
        }
        return json.dumps(data)


class HttpAccessLogJsonFormatter(logging.Formatter):
    """JSON formatter for uvicorn HTTP access logs, extracting fields from standard log format."""

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        style: Literal["%"] | Literal["{"] | Literal["$"] = "%",
    ):
        super(HttpAccessLogJsonFormatter, self).__init__(fmt, datefmt, style)

    @override
    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()

        # This pattern matches uvicorn HTTP access-logs
        # group 1: ip address - digits with periods, digits at the end
        # separator: `:`
        # group 2: port - digits
        # separator: ` - "`
        # group 3: HTTP method - alphanumeric characters
        # separator: whitespace
        # group 4: HTTP path - non-whietspace chartacters
        # separator: whitespace
        # group 5: HTTP version - non-whietspace characters
        # separator: whitespace
        # group 6: HTTP response code - digits
        pattern = r'((?:\d+\.)+\d+)\:(\d+)\s-\s"(\w+)\s(\S+)\s(\S+)"\s(\d+)'
        match = re.search(pattern, message)
        if match is None:
            data = {
                "timestamp": _get_timestamp(),
                "loglevel": getattr(record, "levelname", None),
                "projectName": getattr(record, "name", None),
                "processId": str(os.getpid()),
                "message": message,
            }
        else:
            data = {
                "timestamp": _get_timestamp(),
                "loglevel": getattr(record, "levelname", None),
                "projectName": getattr(record, "name", None),
                "processId": str(os.getpid()),
                "message": message,
                "ip": match.group(1),
                "port": match.group(2),
                "method": match.group(3),
                "path": match.group(4),
                "protocol": match.group(5),
                "status_code": match.group(6),
            }

        return json.dumps(data)
