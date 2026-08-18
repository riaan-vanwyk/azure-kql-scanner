import subprocess
import time
import sys
import json
from azure_client import get_logs_client, get_all_detections, was_detected, get_severity, get_row_count, get_details, print_details, view_avail, DETECTION_LABELS, EXPECTED_FILES, build_report, report_file_name, DETECTIONS_DIR, save_report, past_report_viewer, REPORTS_DIR, load_all_reports, load_single_report, explore_reports, show_frequency_stats, print_health_coverage_check

WORKSPACE_ID = "b859ee5e-7f4d-4fb7-a9b0-0aa14ee15e24"

BANNER = """
==================================================
        Azure Threat Detection Engine v1.0
==================================================
"""

OPTIONS = """[1] Run all detections
[2] Run specific detection
[3] View available detections
[4] Search past threat report(s)
[5] Detection statistics
[0] Exit
"""




def check_login() -> tuple[bool, str]:
    """Verify the Azure CLI is installed and the user is logged in."""
    result_installed = subprocess.run(
        "az", shell=True, capture_output=True, text=True
    )
    if result_installed.returncode != 0:
        return (
            False,
            "Error: Are you sure the Microsoft Azure CLI is installed and added "
            "to PATH, and/or this environment? "
            "https://aka.ms/installazurecliwindows for more information.",
        )

    result_logged_in = subprocess.run(
        "az account show", shell=True, capture_output=True, text=True
    )
    if result_logged_in.returncode != 0:
        return (
            False,
            "Error: The Microsoft Azure CLI is installed and detected, but you "
            "have not logged in to an account yet. Please run <az login> to log "
            "in to your Azure account.",
        )

    return (
        True,
        "Success: The Microsoft Azure CLI is installed and detected in PATH "
        "and/or this environment. An Azure Account was successfully detected. "
        "Continuing.",
    )


def run_all_detections(client, workspace_id: str) -> None:
    """Run every known detection found in the detections folder and report results."""
    start_time = time.time()

    found_files = get_all_detections()
    expected_files = list(DETECTION_LABELS.keys())

    detections_run = 0
    detections_triggered = 0
    detection_info = []  # list of [filename, severity, hit_count]

    print("Running all detections: \nTrying to find the 5 pre-defined files for detections...")

    for filename in expected_files:
        if filename not in found_files:
            print(f"KQL File {filename} was not found in the folder, execution of it was skipped.")
            continue

        print(f"KQL File {filename} found in /detections/ folder")
        detections_run += 1
        label = DETECTION_LABELS[filename]

        print(f"[{detections_run}/{len(expected_files)}] {label} .......... ", end="")
        status = was_detected(client, workspace_id, filename)
        hits = get_row_count(client, workspace_id, filename)
        print(f"{status}\n\tMatches: {hits}")

        if status == "DETECTED":
            detections_triggered += 1
            severity = get_severity(client, workspace_id, filename)
            detection_info.append([filename, severity, hits])

    print("---------------------------------------------------------\nScan Complete\n")
    print("Detections Executed:", detections_run)
    print("Threats Detected:", detections_triggered)

    elapsed = time.time() - start_time
    print(f"Time Elapsed: {elapsed:.2f} seconds\n\nPress enter to view the report...", end="")

    if input() == "":
        print("=========================================================")
        print("Threat Report")
        print("=========================================================")
        for filename, severity, hits in detection_info:
            print(f"\nTechnique\n---------\n{DETECTION_LABELS.get(filename):<12}\n\nSeverity\n---------\n{severity:<10} \n\nMatches\n---------\n{hits}")
            print_details(client, workspace_id, filename)
        for item in get_all_detections():
            if item not in EXPECTED_FILES:
                print(f"File {item} found in the /detections/ folder, that is not part of the 5 pre-defined files of this project.\nHowever, you can choose the [Run specific detection] option to run this query with no problems")

def run_detection(client, workspace_id: str) -> None:
    file = input("Enter the detection file you would like to run in the /detections/ folder: ")

    while file not in get_all_detections():
        if file.lower() == 'k':
            return
        print("The filename you have entered is not present in the folder... Please enter a correct filename (enter 'k' to return to menu): ", end='')
        file = input()
    if file not in EXPECTED_FILES:
        print("Warning: The file you have entered is not in the 5 pre-defined files for this program... Continuing anyway")

    severity = get_severity(client, workspace_id, file)
    hits = get_row_count(client, workspace_id, file)

    technique = DETECTION_LABELS.get(file)
    if technique == None:
        technique = "None - File name not correct or detection not within scope of the project - still running anyway"

    print(f"\nTechnique\n---------\n{technique:<12}\n\nSeverity\n---------\n{severity:<10} \n\nMatches\n---------\n{hits}")
    print_details(client, WORKSPACE_ID, file)

    return file

def main() -> None:
    logged_in, message = check_login()
    print(BANNER)
    print(message)

    if not logged_in:
        return

    client = get_logs_client()
    print("Successfully connected to Azure!")

    print("Options: ")
    print(OPTIONS)

    try:
        choice = int(input("What is your selection: "))
    except ValueError:
        print("Invalid selection.")
        return

    if choice == 1:
        run_all_detections(client, WORKSPACE_ID)
        Inp = input("Would you like to append this last report onto file " + report_file_name() + "? (y/n): ")
        while not (Inp == 'y' or Inp == 'n'):
            Inp = input("Please choose a correct selection (y/n): ")
        if Inp == 'y':
            print(f"Contents {build_report(client, WORKSPACE_ID, get_all_detections())} appended to file {report_file_name()} successfully.")
            save_report(client, WORKSPACE_ID, get_all_detections())
    elif choice == 2:
        file = run_detection(client, WORKSPACE_ID)
        Inp = input("Would you like to append this last report onto file " + report_file_name() + "? (y/n): ")
        while not (Inp == 'y' or Inp == 'n'):
            Inp = input("Please choose a correct selection (y/n): ")
        if Inp == 'y':
            print(file)
            print(f"Contents {build_report(client, WORKSPACE_ID, [file])} appended to file {report_file_name()} successfully.")
            save_report(client, WORKSPACE_ID, [file])
    elif choice == 3:
        view_avail()
    elif choice == 4:
        all_reports = past_report_viewer()
        print("Here are all the filenames of all past reports, please choose an option: ")
        for index, item in enumerate(all_reports):
            print(f"[{index+1}]  {item}")
        print(f"[{index+2}]  Scan all files")
        Inp = input("What is your selection?: ")

        if int(Inp) != index + 2:
            reports_list = load_single_report(all_reports[int(Inp) - 1])
        else:
            reports_list = load_all_reports()

        explore_reports(reports_list)
    elif choice == 5:
        print("[1] Get the Frequency stats per technique (Over ALL the reports in /reports/,  how many times did each specific technique fire? )")
        print("[2] Detection Coverage / Health Check")
        _Inp = input("What is your selection?: ")
        if int(_Inp) == 1:
            # print("about to call the function")
            show_frequency_stats()
        elif int(_Inp) == 2:
            print_health_coverage_check()


    elif choice == 0:
        print("Thank you for using the Azure Threat Detection Engine.")
        sys.exit()
    else:
        print("That option isn't implemented yet.")


if __name__ == "__main__":
    main()
