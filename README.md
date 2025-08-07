<div align="center">
  <h1>🧭 Volume Shadow Copy Explorer (VSCEExplorer)</h1>
  <h3>Explore Volume Shadow Copies (VSCs) from E01 Forensic Images</h3>

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

## 🧠 What is VSCEExplorer?

**VSCEExplorer** is a forensic analysis tool that automates the discovery and exploration of **Volume Shadow Copies (VSCs)** from `.E01` disk images. Built with forensic professionals and cybercrime investigators in mind, this tool provides a clean and intuitive GUI to:

- Detect all available Volume Shadow Snapshots within an image
- Mount and browse each VSC independently
- Recover deleted or historical files
- Perform timeline and artifact analysis over time-based snapshots

---

## 🚀 Features

- 🔍 **Detect & list all VSCs** in loaded E01 disk image
- 📂 **Browse files and folders** from each snapshot like a live file explorer
- 🧭 **Restore deleted or altered files** from historical copies
- 🖼️ Beautiful GUI built with PyQt
- 🧾 Timestamp-based evidence extraction
- 🧪 Built for forensic cases and IR workflows

---

## 🧩 Use Cases

| Scenario | Purpose |
|----------|---------|
| 📅 Restore older file versions | Access user files before deletion |
| 💣 Ransomware recovery | Compare pre/post-infection states |
| 👮 Digital forensics case | Extract historical registry or config files |
| 🛠️ Internal audits | Validate unauthorized changes or tampering |



## 🛠️ Installation

### 🔹 Prerequisites

- Python 3.8 or later
- Works best on **Windows**
- Admin rights recommended (for mounting VSCs)

### 🔹 Setup

```bash
git clone https://github.com/sujayadkesar/vscexplorer.git
cd vscexplorer
pip install -r requirements.txt
python vscexplorer.py

