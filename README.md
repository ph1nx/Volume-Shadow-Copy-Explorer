<div align="center">
  <h1>🧭 Volume Shadow Copy Explorer (VSCExplorer)</h1>
  <h3>Explore Volume Shadow Copies (VSCs) from E01 and RAW Forensic Images including BitLocker Images</h3>

  <p>
    <img src="https://img.shields.io/badge/forensics-VSC%20Analysis-blue?style=flat-square" />
    <img src="https://img.shields.io/github/license/sujayadkesar/vscexplorer?style=flat-square" />
    <img src="https://img.shields.io/github/stars/sujayadkesar/vscexplorer?style=flat-square" />
    <img src="https://img.shields.io/github/issues/sujayadkesar/vscexplorer?style=flat-square" />
    <img src="https://img.shields.io/github/languages/top/sujayadkesar/vscexplorer?style=flat-square" />
  </p>
</div>

---
![image](https://github.com/user-attachments/assets/4526c086-55f1-4ebf-9657-2aea4523158e)
## 🧠 What is VSCExplorer?

**VSCExplorer** is a professional-grade forensic analysis tool that automates the discovery and exploration of **Volume Shadow Copies (VSCs)** from `.E01` or `dd` disk images. Built with forensic professionals and cybercrime investigators in mind, this tool provides a clean and intuitive PyQt-based GUI to:

- 🔍 Detect all available Volume Shadow Snapshots within an image
- 📂 Mount and browse each VSC independently
- 🕰️ Recover deleted or historical files with timestamp preservation
- 📊 Perform timeline and artifact analysis over time-based snapshots
- 💾 Export evidence while maintaining forensic integrity
- `Supports Even Bitlocker Encrypted Images`

## ⭐ Preview of the Tool 
### Main Dashboard
<img width="1392" height="609" alt="Screenshot 2025-08-20 012847" src="https://github.com/user-attachments/assets/07efe236-6e8e-46c5-b177-5f119f3179aa" />
<br><br>

### Bitlocker Decryption and Export UI 
<img width="754" height="521" alt="Screenshot 2025-08-20 085119" src="https://github.com/user-attachments/assets/6ebcfe8f-65ef-484a-9814-2133f713f442" />


## 🚀 Features

### Core Functionality

- 🔍 **VSC Detection & Enumeration even for BitLocker Encrypted Images**
  - Automatic discovery of all available Volume Shadow Snapshots
  - Detailed metadata extraction (creation time, size, VSC ID)
  - Support for multiple VSCs within single E01 image

- 📂 **Interactive File Browser**
  - Tree-view navigation through VSC contents
  - File and folder properties display
  - Search and filter capabilities
  - Thumbnail preview for supported file types

- 💾 **Evidence Export**
  - Selective file and folder extraction
  - Maintain original timestamps and metadata
  - Generate hash verification for exported files
  - Batch export capabilities


## 📋 Prerequisites

#### For Windows:
*There's a compatibility issue with Python 3.12. Please install Python 3.11 from the official Python website: https://www.python.org/downloads/release/python-3110/
<br>

If you don't have Microsoft C++ Build Tools installed, you'll need to install them to compile required packages like libewf-python and pytsk3.

```bash
*If you encounter this error while installing dependencies:

"Microsoft Visual C++ 14.0 or greater is required"
It means your C++ Build Tools are missing or outdated.
Please follow the steps below to install the latest version of "C++ Build Tools".
```

Step 1: Download and Install Microsoft C++ Build Tools - https://visualstudio.microsoft.com/visual-cpp-build-tools/
During the installation, make sure to select the following workloads:
  - Desktop development with C++
  - C++ build tools
  
### Core Dependencies
pytsk3==20250729<br> 
libewf-python==20240506<br> 
libbde-python==20240502<br>
dfvfs


```bash
git clone https://github.com/sujayadkesar/vscexplorer.git
cd vscexplorer
pip install -r requirements.txt
python vscexplorer.py
```

## Acknowledgments & Credits
- [Joachim Metz](https://www.linkedin.com/in/jbmetz/)
For essential forensic libraries such as **libewf** and **libbde**.<br>
These libraries form the foundation for E01, BitLocker, and other image handling capabilities in VSCExplorer.

## 🙌 Contributors

- [Akhil Dara](https://www.linkedin.com/in/akhil-dara/) 
- [Jnana Ramakrishna](https://www.linkedin.com/in/jnana-ramakrishna/)
<br>

Additionally i want to special mention [Akhil Dara](https://www.linkedin.com/in/akhil-dara/) for the major contribution supporting `bitlocker encyrption` and  is the key diffrentiator in the volume shadow copy explorer.
