
#!/usr/bin/env python3
# This script monitors CloudWatch Logs for custom patterns and publishes sanitized alerts to SNS.
# Python 3.11


# ----------- Imports -----------
import os
import time
import json
import logging
import boto3
import re
import botocore
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from time import sleep


# ------------------ Logging Setup ------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ------------------ Configuration (edit embedded patterns here) ------------------
# List of log patterns to monitor. Add/edit patterns as needed.
EMBEDDED_PATTERNS = [
    {
        "name": "DB Connection Timeout",
        "query_filter": r"@message like /org.springframework.dao.DataAccessResourceFailureException/ and @message like /HikariPool-1 - Connection is not available, request timed out/"
    },
    {
        "name": "OutOfMemory Error",
        "query_filter": r"@message like /java.lang.OutOfMemoryError/"
    },
    {
        "name": "HTTP 5xx Errors",
        "query_filter": r"@message like /HTTP\/1\.[01]\" 5[0-9][0-9]/"
    }
]
# ------------------------------------------------------------------------------------


# ------------------ Environment with validation ------------------
# Helper to get integer environment variables with bounds checking
def get_env_int(key: str, default: int, min_val: int = 1, max_val: int = 1000) -> int:
    try:
        value = int(os.environ.get(key, str(default)))
        return max(min_val, min(value, max_val))
    except Exception:
        logger.warning(f"Invalid integer for {key}; using default {default}")
        return default


# Following variables can be overwritten by adding custom env variables
AWS_REGION = os.environ.get("AWS_REGION", None)  # AWS region to use
LOG_GROUP_PREFIX = os.environ.get("LOG_GROUP_PREFIX", "/ecs") # Log group name prefix to search
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")  # SNS topic ARN for alerts
CHUNK_SIZE = get_env_int("CHUNK_SIZE", 10, 1, 50)  # Number of log groups per query chunk
QUERY_WINDOW_MINUTES = get_env_int("QUERY_WINDOW_MINUTES", 5, 1, 60)  # Time window for log search
QUERY_TIMEOUT_SECONDS = get_env_int("QUERY_TIMEOUT_SECONDS", 60, 10, 600)  # Max time to wait for query
SAMPLE_LIMIT = get_env_int("SAMPLE_LIMIT", 3, 1, 20)  # Number of sample log lines per alert
MAX_WORKERS = get_env_int("MAX_WORKERS", 3, 1, 10)  # Thread pool size for parallelism
CACHE_TTL_MINUTES = get_env_int("CACHE_TTL_MINUTES", 60, 5, 1440)  # SSM cache TTL

LOG_GROUPS_CACHE_PARAM = f"/lambda/cw-monitor/log-groups-cache"  # SSM parameter for log group cache
# Cache log groups list in SSM
SSM_CACHE_MAX_BYTES = 3500  # leave headroom under SSM ~4KB limit

SEND_METRICS = os.environ.get("SEND_METRICS", "false").lower() in ("1", "true", "yes")  # Enable CloudWatch metrics

# Query template for CloudWatch Insights
INSIGHTS_QUERY_TEMPLATE = """
fields @timestamp, @message, @logStream, @logGroup
| filter {filter_expr}
| sort @timestamp desc
| limit {limit}
"""


# ------------------ AWS clients (region-aware) ------------------
# Helper to create boto3 clients with region awareness
def boto3_client(name: str):
    if AWS_REGION:
        return boto3.client(name, region_name=AWS_REGION)
    return boto3.client(name)

# AWS service clients
LOGS = boto3_client("logs")
SNS = boto3_client("sns")
SSM = boto3_client("ssm")
CW = boto3_client("cloudwatch") if SEND_METRICS else None


# ------------------ Retry wrapper for throttling/errors ------------------
# Retry decorator for AWS API calls to handle throttling and endpoint errors
def retry_on_throttle(func, *args, max_retries=5, initial_delay=1, **kwargs):
    delay = initial_delay
    for attempt in range(1, max_retries + 1):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("ThrottlingException", "TooManyRequestsException", "LimitExceededException", "Throttling"):
                logger.warning("API throttled (%s). Retrying in %ss (attempt %d/%d)", code, delay, attempt, max_retries)
                sleep(delay)
                delay = min(delay * 2, 30)
                continue
            raise
        except botocore.exceptions.EndpointConnectionError as e:
            logger.warning("Endpoint error: %s. Retrying in %ss (attempt %d/%d)", e, delay, attempt, max_retries)
            sleep(delay)
            delay = min(delay * 2, 30)
            continue
    raise RuntimeError("Max retries exceeded for API call")


# ------------------ Log group caching (SSM) ------------------
# Helper class for caching log group names in SSM Parameter Store
class LogGroupCache:
    @staticmethod
    def get_cached_log_groups(prefix: str) -> Optional[List[str]]:
        try:
            resp = SSM.get_parameter(Name=LOG_GROUPS_CACHE_PARAM)
            val = resp.get("Parameter", {}).get("Value", "")
            if not val:
                return None
            cache_data = json.loads(val)
            cache_time = datetime.fromisoformat(cache_data.get("timestamp"))
            now = datetime.now(timezone.utc)
            age_minutes = (now - cache_time).total_seconds() / 60
            if age_minutes < CACHE_TTL_MINUTES and cache_data.get("prefix") == prefix:
                logger.info("Using cached log groups (age: %.1f min)", age_minutes)
                return cache_data.get("log_groups", [])
        except SSM.exceptions.ParameterNotFound:
            logger.info("No SSM cache found")
        except botocore.exceptions.ClientError as e:
            logger.warning("SSM get_parameter ClientError: %s", e)
        except Exception as e:
            logger.warning("Failed to read SSM cache: %s", e)
        return None

    @staticmethod
    def cache_log_groups(prefix: str, log_groups: List[str]) -> None:
        try:
            cache_data = {
                "prefix": prefix,
                "log_groups": log_groups,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            payload = json.dumps(cache_data)
            if len(payload.encode("utf-8")) > SSM_CACHE_MAX_BYTES:
                logger.info("Cache payload too large (%d bytes); skipping SSM cache", len(payload))
                return
            SSM.put_parameter(
                Name=LOG_GROUPS_CACHE_PARAM,
                Value=payload,
                Type="String",
                Overwrite=True,
                Description="Cached log groups for cw-insights monitor"
            )
            logger.info("Cached %d log groups in SSM", len(log_groups))
        except botocore.exceptions.ClientError as e:
            logger.warning("SSM put_parameter failed: %s", e)
        except Exception as e:
            logger.warning("Failed to cache log groups: %s", e)


# ------------------ Utilities ------------------
# Fetch log groups from CloudWatch, using cache if available
def get_log_groups(prefix: str) -> List[str]:
    cached = LogGroupCache.get_cached_log_groups(prefix)
    if cached is not None:
        return cached

    logger.info("Fetching log groups with prefix: %s", prefix)
    groups: List[str] = []
    next_token = None
    try:
        while True:
            kwargs = {"logGroupNamePrefix": prefix, "limit": 50}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = retry_on_throttle(LOGS.describe_log_groups, **kwargs)
            groups.extend([g["logGroupName"] for g in resp.get("logGroups", [])])
            next_token = resp.get("nextToken")
            if not next_token:
                break
    except Exception as e:
        logger.error("Failed to fetch log groups: %s", e)
        return []

    logger.info("Found %d log groups", len(groups))
    LogGroupCache.cache_log_groups(prefix, groups)
    return groups

# Sanitize sensitive data from log messages before alerting
def sanitize_log_message(message: str) -> str:
    if not message:
        return message
    patterns = [
        (r'password["\s]*[:=]["\s]*[^\s"]+', 'password="[REDACTED]"'),
        (r'token["\s]*[:=]["\s]*[^\s"]+', 'token="[REDACTED]"'),
        (r'secret["\s]*[:=]["\s]*[^\s"]+', 'secret="[REDACTED]"'),
        (r'api[_-]?key["\s]*[:=]["\s]*[^\s"]+', 'apikey="[REDACTED]"'),
        (r'authorization["\s]*:["\s]*[^\s"]+', 'authorization:"[REDACTED]"'),
        (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CARD-REDACTED]'),
        (r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', r'[EMAIL-REDACTED]@\2')
    ]
    sanitized = message
    for pat, repl in patterns:
        sanitized = re.sub(pat, repl, sanitized, flags=re.IGNORECASE)
    if len(sanitized) > 700:
        sanitized = sanitized[:700] + " ... [TRUNCATED]"
    return sanitized

# Yield successive n-sized chunks from a list
def chunks(lst: List, n: int):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]


# ------------------ Insights query execution with retry/backoff ------------------
# Run a CloudWatch Insights query for a chunk of log groups, with polling and retry
def execute_insights_query(log_group_chunk: List[str], query_string: str, start_ts: int, end_ts: int) -> List[Dict[str, Any]]:
    try:
        # Start query with retry wrapper
        resp = retry_on_throttle(
            LOGS.start_query,
            logGroupNames=log_group_chunk,
            startTime=start_ts,
            endTime=end_ts,
            queryString=query_string,
            limit=1000
        )
        query_id = resp.get("queryId")
        if not query_id:
            logger.warning("No queryId returned for chunk")
            return []

        # Poll for results with backoff
        waited = 0
        poll_interval = 2
        while waited < QUERY_TIMEOUT_SECONDS:
            try:
                resp = retry_on_throttle(LOGS.get_query_results, queryId=query_id)
            except Exception as e:
                logger.warning("get_query_results error: %s", e)
                return []

            status = resp.get("status", "")
            if status == "Complete":
                return resp.get("results", [])
            if status in ("Failed", "Cancelled"):
                logger.warning("Query %s ended with status %s", query_id, status)
                return []
            sleep(poll_interval)
            waited += poll_interval

        logger.warning("Insights query %s timed out after %ds", query_id, QUERY_TIMEOUT_SECONDS)
        return []

    except Exception as e:
        logger.error("Query execution failed: %s", e)
        return []


# ------------------ Pattern processing ------------------
# Run a pattern's query across all log groups and build alert objects
def process_pattern(pattern: Dict[str, str], log_groups: List[str], start_ts: int, end_ts: int) -> List[Dict[str, Any]]:
    name = pattern.get("name", "unnamed")
    filter_expr = pattern.get("query_filter")
    if not filter_expr:
        logger.warning("Pattern '%s' missing query_filter", name)
        return []

    query = INSIGHTS_QUERY_TEMPLATE.format(filter_expr=filter_expr, limit=SAMPLE_LIMIT * 2)
    logger.info("Processing pattern '%s' across %d log groups", name, len(log_groups))

    all_results = []
    # Constrain inner parallelism to avoid too many concurrent queries
    inner_workers = max(1, min(MAX_WORKERS, 3))
    with ThreadPoolExecutor(max_workers=inner_workers) as executor:
        futures = {executor.submit(execute_insights_query, chunk, query, start_ts, end_ts): chunk
                   for chunk in chunks(log_groups, CHUNK_SIZE)}
        for f in as_completed(futures):
            try:
                res = f.result()
                if res:
                    all_results.extend(res)
            except Exception as e:
                logger.error("Chunk processing failed for pattern '%s': %s", name, e)

    if not all_results:
        return []

    # Group results by log group
    by_log = {}
    for row in all_results:
        row_map = {col["field"]: col["value"] for col in row}
        lg = row_map.get("@logGroup", "unknown")
        by_log.setdefault(lg, []).append(row_map)

    alerts = []
    for lg, rows in by_log.items():
        samples = []
        for r in rows[:SAMPLE_LIMIT]:
            ts = r.get("@timestamp", "")
            stream = r.get("@logStream", "")
            msg = sanitize_log_message(r.get("@message", ""))
            samples.append(f"{ts} | {stream} | {msg}")
        alerts.append({
            "pattern": name,
            "log_group": lg,
            "matches": len(rows),
            "samples": samples
        })

    return alerts


# ------------------ Publish consolidated SNS alert ------------------
# Publish a summary alert to SNS with all detected pattern matches
def publish_sns_alert(alerts: List[Dict[str, Any]]) -> bool:
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not set; skipping publish")
        return False
    if not alerts:
        return True

    total_matches = sum(a["matches"] for a in alerts)
    pattern_names = sorted({a["pattern"] for a in alerts})

    # Build subject (<=100 chars)
    subject = f"CloudWatch Logs Alert: {total_matches} matches - {', '.join(pattern_names)}"
    if len(subject) > 100:
        subject = subject[:97] + "..."

    message_lines = [
        "🚨 CloudWatch Logs Pattern Detection Alert",
        f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Total Matches: {total_matches}",
        f"Patterns Triggered: {', '.join(pattern_names)}",
        ""
    ]

    by_pattern = {}
    for a in alerts:
        by_pattern.setdefault(a["pattern"], []).append(a)

    for pname, group in by_pattern.items():
        pattern_total = sum(x["matches"] for x in group)
        message_lines.append(f"📋 {pname} ({pattern_total} matches)")
        for alert in group[:5]:
            message_lines.append(f"  • {alert['log_group']}: {alert['matches']} matches")
            for s in alert["samples"][:2]:
                message_lines.append(f"    → {s}")
        if len(group) > 5:
            message_lines.append(f"  ... and {len(group)-5} more log groups")
        message_lines.append("")

    message_lines.append("💡 Check CloudWatch Logs Insights for detailed analysis")

    body = "\n".join(message_lines)
    try:
        SNS.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=body)
        logger.info("Published SNS alert: %d matches across %d alerts", total_matches, len(alerts))
        # optional metric
        if SEND_METRICS and CW:
            try:
                CW.put_metric_data(
                    Namespace="CWMonitor",
                    MetricData=[{"MetricName": "PatternMatches", "Value": total_matches, "Unit": "Count"}]
                )
            except Exception as e:
                logger.warning("Failed to put CloudWatch metric: %s", e)
        return True
    except Exception as e:
        logger.error("Failed to publish SNS alert: %s", e)
        return False


# ------------------ Lambda handler ------------------
# Main Lambda entry point: orchestrates log group fetch, pattern processing, and alerting
def lambda_handler(event, context) -> Dict[str, Any]:
    start = time.time()
    try:
        if not EMBEDDED_PATTERNS:
            logger.info("No embedded patterns configured. Exiting.")
            return {"statusCode": 200, "message": "no patterns"}

        log_groups = get_log_groups(LOG_GROUP_PREFIX)
        if not log_groups:
            logger.info("No log groups found. Exiting.")
            return {"statusCode": 200, "message": "no log groups"}

        end_ts = int(time.time())
        start_ts = end_ts - (QUERY_WINDOW_MINUTES * 60)

        logger.info("Checking %d log groups for %d patterns (window: %d minutes)",
                    len(log_groups), len(EMBEDDED_PATTERNS), QUERY_WINDOW_MINUTES)

        all_alerts = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_pattern = {
                executor.submit(process_pattern, pattern, log_groups, start_ts, end_ts): pattern
                for pattern in EMBEDDED_PATTERNS
            }
            for f in as_completed(future_to_pattern):
                pattern = future_to_pattern[f]
                try:
                    res = f.result()
                    if res:
                        all_alerts.extend(res)
                except Exception as e:
                    logger.error("Pattern '%s' processing failed: %s", pattern.get("name"), e)

        published = False
        if all_alerts:
            published = publish_sns_alert(all_alerts)
        else:
            logger.info("No matches found in this run")

        return {
            "statusCode": 200,
            "alerts_found": len(all_alerts),
            "patterns_checked": len(EMBEDDED_PATTERNS),
            "log_groups_checked": len(log_groups),
            "published_to_sns": published,
            "execution_time_seconds": round(time.time() - start, 2)
        }

    except Exception as e:
        logger.exception("Lambda execution failure: %s", e)
        return {"statusCode": 500, "error": str(e)}

# If you want to run locally for quick smoke tests (requires AWS credentials)
if __name__ == "__main__":
    print(lambda_handler({}, None))