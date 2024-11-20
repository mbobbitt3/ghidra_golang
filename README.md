# Ghidra GoLang 

## Table of Contents
- [About the Project](#about-the-project)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)
- [Contact](#contact)

---

## About the Project
This project adds support to Ghidra for: recovering function names, strings, and types and structures from Go binaries
up to Go version 1.22. And provides samples to test the scripts against.

---

## Features
- Function Name Recovery: allows for recovering all function names from Go program 
- Strings: recovers strings within relevant functions recovered from the name recovery script.
- Type Recovery: recovers types and structures within the program and displays them nicely in decompilation.

---

## Installation
Add the script directory into Ghidra's known script paths to use scripts in GUI or specify location when using headless
mode.
## Usage 
The only thing of note is that the string recovery script is dependent on knowing function names recovered from the name
recovery script, in order to not extract useless strings from the Go Runtime. THis makes the script faster and gives us
relevant strings for malware analysis. This can be changed in the string recovery script should you want to expand the
scope of recovery.

## License
see license.md

## Contact
please email me with questions or concerns at mattbobbitt3@gmail.com. Or feel free to open an issue.
