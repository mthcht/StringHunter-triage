
   .\DLLHound.ps1```
   Required to access process and module details.
   This script is designed for Windows environments only.
   ```powershell
  Add your own directories to the DLL search order for more tailored analysis.
  Displays results in a clean table format directly in the terminal.
  Open the directory of affected executables directly from the script.
  Save the results to a CSV file for further review and reporting.
  Scans all running processes and their loaded DLLs to detect missing or unresolved libraries.
  Set your own size limits for executables and the maximum number of DLL dependencies.
# DLLHound
---
1. **Windows Operating System**  
1. Clone or download this repository to your local system.
1. Run the script with:
2. **PowerShell 5.1 or Later**  
2. Open PowerShell as an administrator.
3. **Administrator Privileges**  
3. Navigate to the script's directory.
A lightweight PowerShell-based scanner designed to identify missing or unresolved DLLs, helping you detect potential DLL sideloading vulnerabilities on your Windows system.
