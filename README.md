# StormFence: A Python-Based Azure detection engine
Personal Website: [🌐 Open My Website](https://riaanvanwyk.onrender.com/index.html)<br><br>
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
#### Description: 
##### 1. Introduction
The core developmental goal of StormFence was to integrate the Microsoft Azure Sentinel environment into the Python runtime via the `azure-identity` and `azure-monitor-query` frameworks provided by Microsoft, allowing you to view, run KQL detections, particularly those defined in the scope of the project as MITRE ATT&CK mapped `T1021.001`, `T1110`, `T1190`, `T1071`, and `T1041`. Although in the `[2] Run specific detection` menu option you can run any detection .kql file that you want to, not just necessarily the 5 pre-defined ones. The Python program also allows you to save/append any detections you might want into a `.json` file, for purposes such as exporting to another potential program or searching past threat reports, or seeing an at-a-glance view (although not very sophisticated) of the previous detections that you have saved. 

In a nutshell, StormFence is a Detection as Code (DaC) tool that runs KQL rules, lays the groundwork for building a fully automated security detection system, and generates reports. 

##### 2. Implementation (By Menu Item)
###### 2.1 Initialization of the program 
As soon as StormFence's `main.py` is started, the program automatically checks if the Microsoft Azure CLI tool is installed and accessible in the current environment, as well as if the user is actually logged in via the Azure CLI system. More specifiaclly, this is implemented in `main.py` via the check_login() command which returns the Go-Ahead status as well as the error / success message, by running `az` and `az account show` via the terminal. 
##### 2.2 Menu Option -- Run All Detections 
When you choose option 1 via the stdin, the `run_all_detections()` function is ran,  which, in a nutshell looks for the 5 pre-defined KQL files inside of the /detections/ folder, if one or more of them are not found, they are simply skipped, and when one a KQL file is found, it executes the detection against the MS Azure Sentinel Workspace, (which is why you need to provide a workspace ID), and prints to the user if there was actually any records present  (`DETECTED vs CLEAN`), and how many records were found. We then calculate a basic severity estimation and also append to a list the information about the particular detection. (Filename, severity, hits). It prints out how many detections were found and how many returned anything, then returning a "threat report" if the user presses Enter, which basically displays a short per-technique summary of what was found, followed by each actual column and row of the table that was returned by the query. If any files were found which were not in the `expected_files` list, it warns the user that he must manually run thenm via option 2. 
##### 2.3 Menu Option -- Run Specific Detection 


- met Sentinel Logseeder , gee vir die die PRESIESE json van my eie environent sodat dit reproducable is 
- - Gee soos `n Tut oor hoe om dit actually up en running op hulle eie account / WS te he . Eie fake logs generate ; 
