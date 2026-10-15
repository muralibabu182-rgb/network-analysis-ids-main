# Network Intrusion Detection System

A Streamlit dashboard for live network packet capture, flow feature extraction, and intrusion detection using a pre-trained TensorFlow model (trained on CIC-IDS2017/2018/2019).

## Requirements (Windows)

- Python 3.10–3.11 recommended
- pip
- Npcap (required for Scapy to sniff packets): https://nmap.org/npcap/
  - During install, enable: "Install Npcap in WinPcap API-compatible Mode"
- Administrator privileges to run packet sniffing
- Model files in `models/` directory:
  - `models/ids_model1.1.h5`
  - `models/scaler.pkl`
  - `models/encoder.pkl`

Python packages are specified in `requirements.txt`:
- streamlit, scapy, tensorflow (2.13+), scikit-learn, pandas, numpy, plotly, openpyxl, joblib, python-dateutil

## Quickstart

1) Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2) Install dependencies

```powershell
pip install -r requirements.txt
```

3) Ensure model files exist

- Verify the three files exist in `models/`. The app will stop and list missing files otherwise.

4) Install Npcap (one time) and run the app as Administrator

- Install Npcap as noted above.
- Open PowerShell as Administrator to allow packet sniffing.

5) Run the Streamlit app

```powershell
streamlit run ids_app.py
```

Open the URL shown in the terminal (usually http://localhost:8501).

## Using the App

- Start/Stop Capture using the control buttons.
- Detection requires at least 30 flows (`config.DETECTION_SETTINGS['min_flows_required']`).
- Export results as CSV/JSON/Excel.

## Troubleshooting

- Scapy shows 0 packets or permission errors:
  - Confirm Npcap is installed and run PowerShell as Administrator.
- TensorFlow install issues on Windows:
  - Use Python 3.10–3.11 and an up-to-date pip.
- Feature mismatch errors during detection:
  - Ensure your model matches the feature order in `config.IDS_FEATURES` and that all three artifacts are present.

## Project Structure

- `ids_app.py` – Streamlit UI and app flow
- `packet_processor.py` – Scapy-based packet and flow processing
- `ids_model.py` – model/scaler/encoder loading and prediction
- `config.py` – feature list and settings
- `visualizations.py`, `ui_components.py`, `styles.py` – charts and UI components
- `models/` – pre-trained model artifacts
