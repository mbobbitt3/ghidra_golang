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
This project extends GoLang analysis capabilities for Ghidra version 10.3.3 (most current version during this project's development) to include: recovering function names, better string recovery, as well as type and structure recovery up to Go version 1.22. Samples are provided to test the scripts against.

---

## Features
- Function Name Recovery: allows for recovering all function names from Go program 
- Strings: recovers strings within relevant functions recovered from the name recovery script (you can modify code to your liking, but default I think is pretty good).
- Type Recovery: recovers types and structures within the program and displays them nicely in decompilation.

---

## Installation
Add the script directory into Ghidra's known script paths to use scripts in GUI or specify location when using headless
mode.
## Usage 
The only thing of note is that the string recovery script is dependent on knowing function names recovered from the name
recovery script, in order to not extract useless strings from the Go Runtime. This makes the script faster and gives us
relevant strings for malware analysis. This can be changed in the string recovery script should you want to expand the
scope of recovery.

## License
See license.md

## Contact
Please email me with questions or concerns at mattbobbitt3@gmail.com. Or feel free to open an issue.
