# 🛡️ Cyber Guard IQ — Advanced Cybersecurity Platform

A full-stack cybersecurity platform with 6 integrated security tools, featuring a modern dark UI with animations and Python-powered analysis.

![Platform](https://img.shields.io/badge/Platform-Node.js%20%2B%20Python-blue)
![Version](https://img.shields.io/badge/Version-2.0-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 🚀 Features

| Tool | Description |
|------|-------------|
| **Phishing Detection** | URL analysis for phishing indicators and suspicious patterns |
| **Password Analyzer** | Strength analysis, HIBP breach check, and secure password generation |
| **SMS Scam Detector** | NLP-powered SMS scam pattern detection with sentiment analysis |
| **Digital Footprint** | Online presence scanning, breach checking, social media discovery |
| **Privacy Checker** | Privacy settings audit for major platforms with recommendations |
| **HackBot Agent** | AI-powered security scanning with interactive terminal simulation |

## 📦 Installation

### Prerequisites
- **Node.js** v16+
- **Python** 3.8+ (optional, for advanced analysis)
- **npm** v8+

### Quick Start

```bash
# 1. Navigate to project directory
cd cyber-defense-platform

# 2. Install Node.js dependencies
cd backend
npm install

# 3. Start the server
npm start

# 4. Open browser at http://localhost:3000
```

### Development Mode

```bash
cd backend
npm.cmd run dev   # Use npm.cmd on Windows if you see a script execution error
```

> [!TIP]
> **Windows Users:** If you get an "Execution Policy" error, use **`npm.cmd`** instead of `npm`, or simply run the provided **`start-platform.bat`** file in the root directory.

### Python Dependencies (Optional)


```bash
pip install requests beautifulsoup4 python-whois nltk textblob
```

> **Note:** Python tools are optional. Each tool has a JavaScript fallback that runs automatically if Python is unavailable.

## 🏗️ Architecture

```
cyber-defense-platform/
├── backend/
│   ├── server.js              # Express server (port 3000)
│   ├── package.json           # Node.js dependencies
│   ├── tools/
│   │   ├── phishing-detection/  # URL phishing analysis
│   │   ├── password-analyzer/   # Password strength + generator
│   │   ├── sms-scam-detector/   # SMS scam classification
│   │   ├── digital-footprint/   # Online presence scanner
│   │   ├── privacy-checker/     # Privacy settings audit
│   │   └── hackbot-agent/       # Security scanning agent
│   └── utils/
│       └── pythonRunner.js    # Python integration utility
├── frontend/
│   ├── index.html             # Main UI
│   ├── styles.css             # Dark theme + animations
│   └── app.js                 # Frontend logic
└── package.json               # Root scripts
```

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | System health check |
| `POST` | `/api/phishing/analyze` | Analyze URL for phishing |
| `POST` | `/api/password/analyze` | Analyze password strength |
| `POST` | `/api/password/generate` | Generate secure password |
| `POST` | `/api/sms/analyze` | Detect SMS scams |
| `POST` | `/api/footprint/scan` | Scan digital footprint |
| `POST` | `/api/privacy/check` | Check privacy settings |
| `POST` | `/api/hackbot/scan` | Start security scan |
| `GET` | `/api/hackbot/status/:id` | Get scan status |

## 🎨 UI Features

- **Dark theme** with blue/cyan accents
- **Glassmorphism** effects with backdrop blur
- **12+ CSS animations**: fadeScale, slideDown, cardAppear, pulseGlow, and more
- **Interactive terminal** simulation for HackBot
- **Real-time** strength meter for passwords
- **Responsive design** for all screen sizes

## 🔑 Environment Variables (Optional)

```env
PORT=3000
HIBP_API_KEY=your_api_key       # Have I Been Pwned
VT_API_KEY=your_api_key         # VirusTotal
GSB_API_KEY=your_api_key        # Google Safe Browsing
```

## ⚠️ Disclaimer

This platform is built for **educational purposes only**. The security scanning tools use simulated data for demonstration. Do not use this tool for unauthorized security testing.

## 📄 License

MIT License — see LICENSE file for details.
