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
