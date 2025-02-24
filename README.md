AI-Powered Intrusion Detection System (AI-PIDS) 🚀
A real-time, AI-driven intrusion detection system leveraging machine learning for high-accuracy threat detection.

📌 Overview
AI-PIDS is an advanced Intrusion Detection System (IDS) that utilizes machine learning (XGBoost) to analyze network traffic and detect malicious activity. It processes live packet captures, extracts key network features, and classifies them in real time.

🔹 Key Features:
✅ Real-time Packet Capture & Analysis using pyshark
✅ AI-Powered Threat Detection with XGBoost
✅ Optimized Preprocessing for handling large datasets (3GB+)
✅ Scalable & GPU Compatible (CUDA Support for Faster Execution)
✅ Logging & Alert System to flag potential intrusions

📂 Project Structure
bash
Copy
Edit
AI-PIDS/
│── data/                     # Data folder (CSV files NOT included)
│   ├── references.md         # Dataset & resource links
│── models/                   # Trained ML models
│── scripts/                  # Helper scripts
│── src/                      # Core AI detection source code
│── .gitignore                # Ignoring large files (CSV, logs, etc.)
│── README.md                 # Project documentation
│── REFERENCES.md              # Dataset sources & references
│── requirements.txt          # Required dependencies
⚙ Installation & Usage
🔹 Step 1: Clone the Repository
sh
Copy
Edit
git clone https://github.com/your-username/AI-PIDS.git
cd AI-PIDS
🔹 Step 2: Install Dependencies
Ensure you have Python 3.8+ installed. Then, run:

sh
Copy
Edit
pip install -r requirements.txt
🔹 Step 3: Ensure Wireshark & TShark are Installed
AI-PIDS requires Wireshark and TShark for live network traffic analysis.

📥 Download Wireshark
🔹 Step 4: Run the AI-PIDS System
sh
Copy
Edit
python src/main.py
📊 Datasets & References
AI-PIDS uses the CIC-IDS2017 dataset for training.
📄 More details and additional datasets are available in REFERENCES.md.

Main Dataset Used:
CIC-IDS2017 (Network Intrusion Detection Dataset)

📥 Download Here
CSE-CIC-IDS2018 (Latest Version for Advanced Threat Detection)

📥 Download Here
🛡 Security & Best Practices
Run with Proper Permissions to analyze network traffic.
Ensure Model is Updated regularly for higher accuracy.
Use a Secure Environment to avoid unauthorized access.
🛠 Technologies Used
Component	Technology
Programming Language	Python 3.8+
Machine Learning	XGBoost
Data Processing	Pandas, NumPy
Network Capture	Pyshark (Wireshark & TShark)
Deployment	Docker (Optional)
📢 Contributing
We welcome contributions! You can help by:
✅ Reporting Issues
✅ Suggesting Enhancements
✅ Submitting Pull Requests

📜 License
This project is licensed under the MIT License.

✨ Improvements Made
✔ Professional Formatting – Clear sections and markdown styling
✔ Detailed Documentation – Explains every step for new users
✔ Enhanced Readability – Code blocks, icons, and tables for clarity
✔ Security Best Practices – Important considerations before deployment

Let me know if you need further refinements! 🚀