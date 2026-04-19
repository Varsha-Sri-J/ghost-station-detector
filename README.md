
# Ghost Station Detector

A cybersecurity solution to detect rogue EV charging stations using dynamic trust evaluation and runtime monitoring.

## Problem
EVs trust charging stations without continuous verification, making them vulnerable to spoofing and malicious behaviour.

## Solution
Ghost Station Detector continuously:
- Verifies station identity
- Monitors runtime behaviour
- Computes a dynamic trust score
- Decides to allow, restrict, or block charging

## Features
- Real-time trust scoring
- Attack simulation (rogue station)
- Live security dashboard
- Decision engine (Allow / Restrict / Block)

## Tech Stack
- Python
- Streamlit

## How to Run
```bash
pip install -r requirements.txt
streamlit run dashboard.py
