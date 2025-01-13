# DLLHound
# DLL Sideloading Scanner 🔍

A lightweight PowerShell-based scanner designed to identify missing or unresolved DLLs, helping you detect potential DLL sideloading vulnerabilities on your Windows system.

---

## Features ✨

- **Dynamic Process Analysis** 🔄  
  Scans all running processes and their loaded DLLs to detect missing or unresolved libraries.

- **Customizable Search Paths** 🛠️  
  Add your own directories to the DLL search order for more tailored analysis.

- **Custom Scans** 📏  
  Set your own size limits for executables and the maximum number of DLL dependencies.

- **Clear, Organized Output** 🗂️  
  Displays results in a clean table format directly in the terminal.

- **CSV Export** 📄  
  Save the results to a CSV file for further review and reporting.

- **Quick Access to Affected Files** 🚪  
  Open the directory of affected executables directly from the script.

---

## Requirements 🖥️

1. **Windows Operating System**  
   This script is designed for Windows environments only.
2. **PowerShell 5.1 or Later**  
   Ensure you’re running an updated version of PowerShell.
3. **Administrator Privileges**  
   Required to access process and module details.

---

## Installation 🛠️

1. Clone or download this repository to your local system.
2. Open PowerShell as an administrator.
3. Navigate to the script's directory.

---

## Usage 🚀

1. Run the script with:
   ```powershell
   .\DLLHound.ps1```
