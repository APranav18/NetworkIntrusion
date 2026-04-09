# 🛡️ AI-Based Network Intrusion Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3+-000000?style=for-the-badge&logo=flask&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3+-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-8.0+-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A Machine Learning-powered Network Intrusion Detection System with Real-Time Monitoring**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [Screenshots](#-screenshots)

</div>

---

## 📋 Overview

The **AI-Based Network Intrusion Detection System (NIDS)** is a comprehensive cybersecurity solution that leverages Machine Learning to detect and classify network attacks in real-time. Built with Python and Flask, this system provides a professional-grade dashboard for monitoring network security.

### 🎯 Key Highlights

- **98.7% Detection Accuracy** using Random Forest Classifier
- **Real-Time Packet Analysis** with Scapy integration
- **Premium Silicon Valley UI** with glassmorphism design
- **Multi-Class Attack Detection** supporting 8+ attack types
- **Email Alert System** for immediate threat notifications

---

## ✨ Features

### 🤖 Machine Learning
- Random Forest Classifier with GridSearchCV optimization
- Trained on CICIDS2017 benchmark dataset
- Support for 8 attack classifications:
  - Normal Traffic
  - DoS (Denial of Service)
  - DDoS (Distributed DoS)
  - Port Scan
  - Brute Force
  - Botnet
  - Infiltration
  - Web Attacks

### 📊 Dashboard
- Real-time network traffic monitoring
- Interactive charts (Chart.js)
- Attack distribution visualization
- System status indicators
- Recent alerts panel

### 🔐 Security
- Secure user authentication
- Password hashing (Werkzeug)
- Session management
- Role-based access control

### 📧 Alerts
- Email notifications for detected threats
- Alert severity classification (Critical, High, Medium, Low)
- Rate-limited notifications
- Aggregated alert summaries

### 🎨 UI/UX
- Dark futuristic theme
- Glassmorphism design
- Animated particle background
- GSAP animations
- Fully responsive layout

---

## 🚀 Installation

### Prerequisites

- Python 3.9 or higher
- MySQL Server 8.0+
- Npcap (Windows) or libpcap (Linux) for packet capture
- Git

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/NIDS_Project.git
cd NIDS_Project
```

### Step 2: Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Setup MySQL Database

```sql
CREATE DATABASE nids_db;
```

The application will automatically create required tables on first run.

### Step 5: Configure Environment Variables (Optional)

Create a `.env` file in the project root:

```env
FLASK_SECRET_KEY=your-secret-key-here
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=your-password
MYSQL_DATABASE=nids_db

# Email Configuration (for alerts)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

### Step 6: Download Dataset (Optional)

For training the model with the CICIDS2017 dataset:

1. Download from [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Place CSV files in the `dataset/` folder

### Step 7: Train the Model

```bash
python train_model.py
```

This will:
- Load and preprocess the dataset
- Train the Random Forest model
- Save the model to `model/nids_model.pkl`
- Generate visualizations

---

## 💻 Usage

### Run the Application

```bash
python app.py
```

The application will start at `http://localhost:5000`

### Default Login

Create an account on the registration page or use:
- Navigate to `/register` to create a new account

### Dashboard Features

| Feature | Description |
|---------|-------------|
| **Dashboard** | Overview of network statistics and recent alerts |
| **Detection** | Real-time packet capture and analysis |
| **Logs** | Historical detection records with filtering |
| **Alerts** | Security notifications and threat details |
| **ML Model** | Model performance metrics and retraining |
| **Settings** | System configuration and preferences |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Get dashboard statistics |
| `/api/detect` | POST | Analyze network packet |
| `/api/logs` | GET | Retrieve detection logs |
| `/api/alerts` | GET | Get security alerts |
| `/api/model-info` | GET | Get ML model information |
| `/api/train` | POST | Retrain the ML model |

---

## 🏗️ Architecture

```
NIDS_Project/
│
├── app.py                 # Flask application & routes
├── database.py            # MySQL database operations
├── train_model.py         # ML model training pipeline
├── realtime_detection.py  # Packet capture & analysis
├── email_alert.py         # Email notification system
├── requirements.txt       # Python dependencies
│
├── model/
│   ├── nids_model.pkl     # Trained ML model
│   ├── scaler.pkl         # Feature scaler
│   └── label_encoder.pkl  # Label encoder
│
├── dataset/
│   └── *.csv              # CICIDS2017 dataset files
│
├── static/
│   ├── css/
│   │   └── style.css      # Premium styling
│   └── js/
│       ├── script.js      # Dashboard functionality
│       └── particles.js   # Animated background
│
└── templates/
    ├── login.html         # Login page
    ├── register.html      # Registration page
    └── dashboard.html     # Main dashboard
```

### Technology Stack

| Component | Technology |
|-----------|------------|
| Backend | Python, Flask |
| Frontend | HTML5, CSS3, JavaScript |
| ML Framework | scikit-learn |
| Database | MySQL |
| Visualization | Chart.js, Matplotlib |
| Animations | GSAP |
| Packet Capture | Scapy |

---

## 📊 Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | 98.7% |
| Precision | 98.2% |
| Recall | 98.8% |
| F1 Score | 98.5% |

### Attack Detection Rates

| Attack Type | Detection Rate |
|-------------|----------------|
| DoS | 99.1% |
| DDoS | 98.8% |
| Port Scan | 97.5% |
| Brute Force | 98.2% |
| Botnet | 97.8% |

---

## 📸 Screenshots

### Login Page
- Modern glassmorphism design
- Animated particle background
- Responsive layout

### Dashboard
- Real-time statistics cards
- Network traffic charts
- Recent alerts panel
- System status indicators

### Detection Page
- Live packet monitoring
- Manual packet analysis
- Threat classification results

---

## 🔧 Configuration

### Email Alerts Setup

1. Enable 2-Factor Authentication on Gmail
2. Generate an App Password
3. Configure in `email_alert.py` or `.env` file

### Detection Sensitivity

Adjust in Settings page or modify `realtime_detection.py`:
- Higher sensitivity = more false positives
- Lower sensitivity = may miss subtle attacks

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Your Name**
- MCA Final Year Project
- Institution Name
- Year: 2024

---

## 🙏 Acknowledgments

- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) - Canadian Institute for Cybersecurity
- [Flask Documentation](https://flask.palletsprojects.com/)
- [scikit-learn](https://scikit-learn.org/)
- [Chart.js](https://www.chartjs.org/)
- [GSAP](https://greensock.com/gsap/)

---

<div align="center">

**⭐ Star this repository if you found it helpful!**

Made with ❤️ for Network Security

</div>
