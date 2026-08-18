from datetime import timedelta
from pathlib import Path

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

import json
import os
import uuid
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = BASE_DIR / "detections"
REPORTS_DIR = BASE_DIR / "reports"

JSON_REPORT = {}



# Base severity per detection technique (MITRE ATT&CK ID -> severity)
BASE_SEVERITY = {
    "T1021_001.kql": "HIGH",      # Remote Services: RDP
    "T1110.kql":     "MEDIUM",      # Brute Force
    "T1190.kql":     "HIGH",      # Exploit Public-Facing Application
    "T1071.kql":     "CRITICAL",  # Application Layer Protocol (C2)
    "T1041.kql":     "CRITICAL",  # Exfiltration Over C2 Channel
}

# Maps each known .kql filename to a human-readable label for display
DETECTION_LABELS = {
    "T1021_001.kql": "T1021.001 - Remote Services: Remote Desktop Protocol",      # Remote Services: RDP
    "T1110.kql":     "T1110 - Brute Force",      # Brute Force
    "T1190.kql":     "T1190 - Exploit Public-Facing Application",      # Exploit Public-Facing Application
    "T1071.kql":     "T1071 - Application Layer Protocol",  # Application Layer Protocol (C2)
    "T1041.kql":     "T1041 - Exfiltration Over C2 Channel",  # Exfiltration Over C2 Channel
}

EXPECTED_FILES = ["T1021_001.kql", "T1110.kql", "T1190.kql", "T1071.kql", "T1041.kql"]

def get_logs_client() -> LogsQueryClient:
    """Create an authenticated Log Analytics query client."""
    credential = DefaultAzureCredential()
    return LogsQueryClient(credential)


def load_query(query_file: str) -> str:
    """Read a KQL query's text from the detections directory."""
    path = DETECTIONS_DIR / query_file
    return path.read_text(encoding="utf-8")


def run_query(client: LogsQueryClient, workspace_id: str, query_file: str):
    """Run a KQL query against a workspace.

    Uses an effectively unbounded timespan because each .kql file is
    expected to define its own time range. This avoids silently
    truncating results to a default window (e.g. 1 day) when a query
    actually needs a longer lookback.
    """
    query = load_query(query_file)
    return client.query_workspace(
        workspace_id=workspace_id,
        query=query,
        timespan=timedelta(days=10000),
    )


def get_row_count(client: LogsQueryClient, workspace_id: str, query_file: str) -> int:
    """Return the number of result rows for a query, or 0 if none."""
    response = run_query(client, workspace_id, query_file)
    if not response.tables:
        return 0
    return len(response.tables[0].rows)


def was_detected(client: LogsQueryClient, workspace_id: str, query_file: str) -> str:
    """Return 'DETECTED' if the query returned any rows, else 'CLEAN'."""
    return "DETECTED" if get_row_count(client, workspace_id, query_file) > 0 else "CLEAN"


def get_severity(client: LogsQueryClient, workspace_id: str, query_file: str) -> str:
    """Determine severity, escalating based on hit volume.

    Falls back to a per-technique base severity when hit count is low.
    """
    hits = get_row_count(client, workspace_id, query_file)

    if hits >= 10:
        return "CRITICAL"
    if hits >= 5:
        return "HIGH"
    return BASE_SEVERITY.get(query_file, "MEDIUM")


def get_all_detections() -> list[str]:
    """List all .kql detection files in the detections directory.

    Source: https://stackoverflow.com/a/3207973
    Posted by pycruft, modified by community; retrieved 2026-08-06.
    License: CC BY-SA 4.0
    """
    return [f.name for f in DETECTIONS_DIR.iterdir() if f.is_file() and f.suffix == ".kql"]

def get_details(client: LogsQueryClient, workspace_id: str, query_file: str) -> list[dict]:
    """Return every record from a query as a list of dicts, keyed by whatever
    columns the .kql file itself projects (e.g. TimeGenerated, OperationNameValue,
    Caller, ResourceGroup, ActivityStatusValue).

    This makes get_details agnostic to which fields a given detection selects —
    add or remove columns in the .kql file and this function picks them up
    automatically, no code changes needed here.
    """
    response = run_query(client, workspace_id, query_file)
    if not response.tables:
        return []

    table = response.tables[0]
    columns = table.columns

    return [dict(zip(columns, row)) for row in table.rows]

def print_details(client: LogsQueryClient, workspace_id: str, query_file: str) -> None:
    """Print each record's fields as a name/value block, in the order the
    .kql file projects them.
    """
    records = get_details(client, workspace_id, query_file)

    if not records:
        print("No records found.")
        return

    for i, record in enumerate(records, start=1):
        print(f"=========== Record {i}/{len(records)} ===========")
        for column_name, value in record.items():
            print(f"{column_name}\n----------\n{value}\n")

def view_avail():
    for item in list(set(EXPECTED_FILES + get_all_detections())):
        corresponds = DETECTION_LABELS.get(item);
        if item not in get_all_detections():
            corresponds = f"Missing - not actually in the folder. Consider making a new file {item}"
        if corresponds == None:
            corresponds = "None - outside of the scope of the 5 types of detections of this project - you can still run it via Option [Run specific detection]"
        print(f"File Name:         \t\t{item}\nCorresponds to: \t\t{corresponds}", end='\n\n')





def build_report(client, workspace_id: str, filenames: list[str]) -> dict:
    """Build a single report dict, structured exactly like:

    {
      "ReportId": "...",
      "ReportTimestamp": "...",
      "Files": [...],
      "Detections": {
          "<filename>": {
              "Technique": "...",
              "Severity": "...",
              "Matches": N,
              "Records": [{"RecordId": i, "Fields": {...}}, ...]
          },
          ...
      }
    }

    filenames: the list of .kql files that were run to produce this report
    (e.g. only the ones that returned DETECTED, or all of them — caller decides).
    """
    detections = {}

    for filename in filenames:
        records = get_details(client, workspace_id, filename)
        hits = len(records)

        detections[filename] = {
            "Technique": DETECTION_LABELS.get(filename, "Unknown"),
            "Severity": get_severity(client, workspace_id, filename),
            "Matches": hits,
            "Records": [
                {"RecordId": i, "Fields": record}
                for i, record in enumerate(records, start=1)
            ],
        }

    report = {
        "ReportId": str(uuid.uuid4()),
        "ReportTimestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Files": filenames,
        "Detections": detections,
    }

    return report

def json_serializer(obj):
    """Convert datetime objects to ISO format strings for JSON."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def report_file_name():
    report_path = REPORTS_DIR / datetime.now(timezone.utc).strftime("report_%Y_%m_%d.json")
    return(str(report_path))
def save_report(client, workspace_id, filenames):
    new_report = build_report(client, workspace_id, filenames)
    
    data = []
    if os.path.exists(report_file_name()) and os.path.getsize(report_file_name()) > 0:
        try:
            with open(report_file_name(), "r") as f:
                content = f.read().strip()
                if content:  # Only parse if there's actual content
                    data = json.loads(content)
                else:
                    data = []
        except json.JSONDecodeError:
            print(f"Warning: {report_file_name()} was corrupt. Starting fresh.")
            data = []
    else:
        print(f"Creating new report: {report_file_name()}")

    data.append(new_report)

    with open(report_file_name(), "w") as f:
        json.dump(data, f, indent=2, default=json_serializer)


def past_report_viewer():
    return [f.name for f in REPORTS_DIR.iterdir() if f.is_file() and f.suffix == ".json"]


def load_all_reports() -> list:
    """Load every saved report file under REPORTS_DIR into one combined list
    of report dicts, normalizing files that may contain a single report dict
    or an array of report dicts.
    """
    all_reports = []
    for report_file in sorted(f.name for f in REPORTS_DIR.iterdir() if f.is_file() and f.suffix == ".json"):
        with open(REPORTS_DIR / report_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            if isinstance(loaded, list):
                all_reports.extend(loaded)
            else:
                all_reports.append(loaded)
    return all_reports


def load_single_report(filename: str) -> list:
    """Load one report file, normalized into a list of report dicts
    (handles both the single-dict and array-of-dicts file shapes)."""
    with open(REPORTS_DIR / filename, "r", encoding="utf-8") as f:
        loaded = json.load(f)
        return loaded if isinstance(loaded, list) else [loaded]


def _print_report(json_logging: dict) -> None:
    """Print one report dict in the standard block format."""
    print(f"\nReportId\n---------\n{json_logging.get('ReportId')}\n")
    print(f"ReportTimestamp\n---------\n{json_logging.get('ReportTimestamp')}\n")
    print(f"Files\n---------\n{json_logging.get('Files')}\n")

    for filename, detection in json_logging.get("Detections", {}).items():
        print(f"\n--- {filename} ---")
        print(f"Technique\n---------\n{detection.get('Technique')}\n")
        print(f"Severity\n---------\n{detection.get('Severity')}\n")
        print(f"Matches\n---------\n{detection.get('Matches')}\n")

        records = detection.get("Records", [])
        if not records:
            print("No records found.\n")
            continue

        for record in records:
            print(f"=========== Record {record.get('RecordId')} ===========")
            for field_name, value in record.get("Fields", {}).items():
                print(f"{field_name}\n----------\n{value}\n")


def explore_reports(reports_list: list) -> None:
    """Given a list of loaded report dicts, show the view/search sub-menu
    and act on the user's selection. Shared by both the single-file and
    'scan all files' paths in main.py.
    """
    print("File(s) successfully loaded. Please choose one of the following options:\n"
          "[1] View The entire file(s) as raw .json\n"
          "[2] View the entire file(s), but formatted nicely\n"
          "[3] Search for a specific ReportID and view only that, formatted nicely\n"
          "[4] Search for a specific record(s) by Column and cell value ")
    Inp_ = int(input("What is your selection?: "))

    if Inp_ == 1:
        print(reports_list)

    elif Inp_ == 2:
        for json_logging in reports_list:
            _print_report(json_logging)

    elif Inp_ == 3:
        target_id = input("Enter the ReportId to view: ").strip()
        found = False
        for json_logging in reports_list:
            if json_logging.get("ReportId") == target_id:
                found = True
                _print_report(json_logging)
        if not found:
            print(f"No report with ReportId {target_id} found.")

    elif Inp_ == 4:
        column = input("Enter the column/field name to search (e.g. Caller): ")
        value = input("Enter the value to search for: ")
        found = False
        for json_logging in reports_list:
            for filename, detection in json_logging.get("Detections", {}).items():
                for record in detection.get("Records", []):
                    fields = record.get("Fields", {})
                    if column in fields and value.lower() in str(fields[column]).lower():
                        found = True
                        print(f"\n--- {filename} ---")
                        print(f"=========== Record {record.get('RecordId')} ===========")
                        for field_name, field_value in fields.items():
                            print(f"{field_name}\n----------\n{field_value}\n")
        if not found:
            print(f"No records found where {column} contains '{value}'.")

    else:
        print("Invalid selection.")


def show_frequency_stats():
    reports_list = load_all_reports()
    counts = {filename: 0 for filename in get_all_detections()}

    for report in reports_list:
        for filename, detection in report.get("Detections", {}).items():
            if detection.get("Matches", 0) > 0:
                counts[filename] = counts.get(filename, 0) + 1

    print("Detection Frequency (across all saved reports)\n==================================================")
    print(f"{'Technique':<50}{'Amount':>5}")
    for item in counts:
        if DETECTION_LABELS.get(item) != None:
            print(f"{DETECTION_LABELS.get(item):<50}{str(counts.get(item)):>5}")
        else:
            print(f"{item:<50}{str(counts.get(item)):>5}")
def coverage_health_check() -> dict:
    """Check which detection files have ever fired vs never fired,
    across all saved reports, plus how many reports had zero detections
    at all (a fully clean scan).
    """
    reports_list = load_all_reports()

    ever_fired = set()
    clean_reports = 0

    for report in reports_list:
        report_had_hit = False
        for filename, detection in report.get("Detections", {}).items():
            if detection.get("Matches", 0) > 0:
                ever_fired.add(filename)
                report_had_hit = True
        if not report_had_hit:
            clean_reports += 1

    all_known = set(get_all_detections())
    never_fired = all_known - ever_fired

    return {
        "ever_fired": sorted(ever_fired),
        "never_fired": sorted(never_fired),
        "clean_reports": clean_reports,
        "total_reports": len(reports_list),
    }
def print_health_coverage_check() -> None:
    result = coverage_health_check()

    print("Detection Coverage / Health Check")
    print("=" * 50)

    print("\nTechniques that HAVE fired at least once:")
    for filename in result["ever_fired"]:
        print(f"  - {DETECTION_LABELS.get(filename, filename)}")

    print("\nTechniques that have NEVER fired:")
    if result["never_fired"]:
        for filename in result["never_fired"]:
            print(f"  - {DETECTION_LABELS.get(filename, filename)}")
    else:
        print("  (none — every known technique has fired at least once)")

    print(f"\nClean reports (zero detections): {result['clean_reports']} / {result['total_reports']}")
