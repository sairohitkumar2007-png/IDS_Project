# IoT Intrusion Detection System (IDS)

## Project Overview
This project implements a simple Intrusion Detection System for IoT environments.  
It detects malicious patterns in incoming data using different detection techniques.

The system simulates how IoT devices send data to a gateway and how the gateway
detects attacks using pattern matching algorithms.

## Features
- Detects attack patterns in incoming IoT traffic
- Supports multiple IDS techniques:
  - List-based IDS
  - Hash-based IDS
  - Trie-based IDS (Aho-Corasick)
- Generates alerts for detected attacks
- Quarantines suspicious inputs
- Allows remote command input using a mobile device

## Technologies Used
- C++ (core IDS implementation)
- Python (Flask server for remote commands)
- File-based simulation of IoT network

## Project Structure
main.cpp → IDS detection algorithms
server.py → Flask server for mobile commands
patterns.txt → Known attack patterns
cloud_in.txt → Incoming network traffic
alerts.txt → Detected attacks log
quarantine.txt → Suspicious packets


## How It Works
1. IoT devices send input data.
2. The gateway receives the data.
3. IDS scans the data for known attack patterns.
4. If a match is found:
   - Alert is generated
   - Data is quarantined

## Running the Project

### Compile IDS
g++ main.cpp -o ids

### Run IDS
./ids

### Run Flask Server
py server.py


## Future Improvements
- Real network packet capture
- Machine learning based detection
- Web dashboard for alerts

## Author
Rohit Kumar
