# Node.js Automatic DDoS Protection Script

This project provides an automatic DDoS protection script written in Node.js. It monitors incoming connections, detects suspicious activity, and blocks potential DDoS attacks based on configurable rules.

## Features
- Monitors access and connection logs
- Detects suspicious patterns and payloads
- Blocks malicious IPs automatically
- Configurable settings and payloads
- Logs user activity and detected threats

## Setup Instructions

### Prerequisites
- [Node.js](https://nodejs.org/) (v12 or higher recommended)

### Installation
1. **Clone or Download the Repository**
   - Download the project files to your local machine.

2. **Install Dependencies**
   - Open a terminal in the project directory and run:
     ```powershell
     npm install
     ```
   - (If there is no `package.json`, dependencies may be bundled or not required.)

3. **Configure Settings**
   - Edit `assets/config.json` to adjust detection thresholds, block settings, and other options as needed.
   - Review other files in the `assets/` folder for additional configuration (e.g., `payloads.txt`, `block_setting.txt`).

4. **Run the Script**
   - Start the protection script with:
     ```powershell
     node index.js
     ```

## Files and Folders
- `index.js` — Main script file
- `assets/` — Contains configuration, logs, and detection data:
  - `config.json` — Main configuration file
  - `payloads.txt` — List of suspicious payloads
  - `block_setting.txt` — Block settings
  - `access-logs.txt`, `connection-logs.txt`, `user-activity-logs.txt` — Log files
  - `detected.json` — Detected threats
  - `setup.txt` — Setup notes

## Notes
- Ensure the script has permission to read/write files in the `assets/` directory.
- Regularly review logs and detected threats for false positives.
- Adjust configuration as needed for your environment.

## License
This project is provided as-is for educational and security research purposes.
