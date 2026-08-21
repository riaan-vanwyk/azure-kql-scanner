# StormFence: A Python-Based Azure detection engine
Personal Website: [🌐 Open My Website](https://riaanvanwyk.onrender.com/index.html)<br><br>
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
#### Description: 
##### 1. Introduction
The core developmental goal of StormFence was to integrate the Microsoft Azure Sentinel environment into the Python runtime via the `azure-identity` and `azure-monitor-query` frameworks provided by Microsoft, allowing you to view, run KQL detections, particularly those defined in the scope of the project as MITRE ATT&CK mapped `T1021.001`, `T1110`, `T1190`, `T1071`, and `T1041`. Although in the `[2] Run specific detection` menu option you can run any detection .kql file that you want to, not just necessarily the 5 pre-defined ones. The Python program also allows you to save/append any detections you might want into a `.json` file, for purposes such as exporting to another potential program or searching past threat reports, or seeing an at-a-glance view (although not very sophisticated) of the previous detections that you have saved. 

In a nutshell, StormFence is a Detection as Code (DaC) tool that runs KQL rules, lays the groundwork for building a fully automated security detection system, and generates reports. 

purpose and function 


