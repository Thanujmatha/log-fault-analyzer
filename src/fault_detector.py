
import re
import pandas as pd


# Specific failure patterns should come before broader patterns.
PATTERNS = [
    (
        "Database timeout",
        re.compile(
            r"database.{0,80}(?:timed?\s*out|timeout)|"
            r"\bdb\b.{0,80}(?:timed?\s*out|timeout)|"
            r"connection timed out|query timed out|"
            r"statement timeout|lock wait timeout",
            re.I,
        ),
        "Check database availability, query latency, network connectivity, "
        "and timeout settings.",
    ),
    (
        "Database connection pool saturation",
        re.compile(
            r"connection pool.{0,50}(?:exhausted|saturat|usage high|"
            r"limit reached|timeout)|"
            r"pool exhausted|too many database connections",
            re.I,
        ),
        "Inspect active and maximum pool connections, connection leaks, "
        "query duration, and pool limits.",
    ),
    (
        "Database connection failure",
        re.compile(
            r"connection refused|could not connect to (?:the )?database|"
            r"failed to connect to (?:the )?database|"
            r"unable to connect to (?:the )?database|"
            r"database connection failed|"
            r"database unavailable|connection establishment failed",
            re.I,
        ),
        "Check database health, credentials, network access, "
        "and connection configuration.",
    ),
    (
        "Payment processing failure",
        re.compile(
            r"payment processing (?:unavailable|failed|failure)|"
            r"payment gateway.{0,50}(?:unavailable|failed|timeout|error)|"
            r"payment transaction failed",
            re.I,
        ),
        "Check payment gateway health, dependency status, response codes, "
        "and transaction logs.",
    ),
    (
        "Checkout failure",
        re.compile(
            r"checkout (?:failed|failure|unavailable)|"
            r"failed to (?:complete|process) checkout",
            re.I,
        ),
        "Inspect checkout logs, payment dependencies, request IDs, "
        "and transaction state.",
    ),
    (
        "HTTP 5xx/server failure",
        re.compile(
            r"\bhttp\s*5\d\d\b|"
            r"\bstatus\s*[=: ]\s*5\d\d\b|"
            r"internal server error|server returned 5\d\d",
            re.I,
        ),
        "Inspect the application stack trace and upstream dependencies "
        "for the affected request.",
    ),
    (
        "Application latency",
        re.compile(
            r"request latency elevated|"
            r"response time (?:high|elevated|slow)|"
            r"slow request|request timed out|"
            r"latency above threshold",
            re.I,
        ),
        "Inspect request latency percentiles, traces, database query "
        "duration, and upstream service response times.",
    ),
    (
        "Authentication/authorization failure",
        re.compile(
            r"unauthorized|forbidden|authentication failed|"
            r"invalid token|permission denied|access denied",
            re.I,
        ),
        "Verify identity, token expiry, permissions, and recent "
        "authentication configuration changes.",
    ),
    (
        "Memory/resource pressure",
        re.compile(
            r"out of memory|\boom\b|memory exhausted|"
            r"too many open files|resource exhaustion",
            re.I,
        ),
        "Inspect memory and resource metrics, workload changes, "
        "file descriptors, and resource limits.",
    ),
    (
        "Disk/storage issue",
        re.compile(
            r"disk full|no space left|storage exhausted|"
            r"read-only file system",
            re.I,
        ),
        "Check disk capacity, inode usage, volume health, "
        "and log retention.",
    ),
    (
        "Network/DNS issue",
        re.compile(
            r"dns resolution failed|name resolution failed|"
            r"network unreachable|connection reset|broken pipe",
            re.I,
        ),
        "Check DNS resolution, network routes, service reachability, "
        "and connection resets.",
    ),
    (
        "Application exception",
        re.compile(
            r"\bexception\b|\btraceback\b|"
            r"uncaught error|\bpanic:",
            re.I,
        ),
        "Inspect the complete stack trace and identify the first "
        "application frame.",
    ),
]


def detect_faults(df):
    """Classify log events and attach evidence-based diagnostic actions."""

    out = df.copy()

    if out.empty:
        out["fault_category"] = pd.Series(index=out.index, dtype="object")
        out["suggested_action"] = pd.Series(index=out.index, dtype="object")
        out["is_fault"] = pd.Series(index=out.index, dtype=bool)
        return out

    categories = []
    actions = []
    is_fault = []

    for _, row in out.iterrows():
        level = str(row.get("level", "INFO")).strip().upper()
        message = str(row.get("message", ""))
        text = f"{level} {message}"

        category = "Unclassified"
        action = "Review surrounding events and application context."

        # Ignore ordinary success/initialization messages unless they
        # contain an explicit failure pattern.
        success_only = bool(
            re.search(
                r"\b(?:initialized|initialised|started successfully|"
                r"connected successfully|connection established|"
                r"healthy|recovered|completed successfully)\b",
                message,
                re.I,
            )
        )

        for name, pattern, recommendation in PATTERNS:
            if pattern.search(text):
                category = name
                action = recommendation
                break

        if success_only and category != "Unclassified":
            # Keep explicit failures even if the same line mentions
            # recovery or initialization; do not suppress real errors.
            explicit_failure = bool(
                re.search(
                    r"\b(?:error|failed|failure|timeout|timed out|"
                    r"refused|unavailable|exhausted|exception|"
                    r"critical|unreachable)\b",
                    text,
                    re.I,
                )
            )
            if not explicit_failure:
                category = "Unclassified"
                action = "No explicit fault detected; message appears informational."

        fault = (
            level in {"WARNING", "ERROR", "CRITICAL"}
            or category != "Unclassified"
        )

        categories.append(category)
        actions.append(action)
        is_fault.append(fault)

    out["fault_category"] = categories
    out["suggested_action"] = actions
    out["is_fault"] = is_fault

    return out
