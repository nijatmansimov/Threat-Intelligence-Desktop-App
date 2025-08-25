import sys
import json
import requests
import hashlib
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, 
                             QGroupBox, QRadioButton, QFileDialog, QMessageBox, QFormLayout)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

class ThreatIntelligenceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.load_settings()
        
    def initUI(self):
        self.setWindowTitle('Threat Intelligence Analyzer')
        self.setGeometry(100, 100, 800, 600)
        
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tabs
        self.tabs = QTabWidget()
        self.scan_tab = QWidget()
        self.settings_tab = QWidget()
        
        self.tabs.addTab(self.scan_tab, "Scan")
        self.tabs.addTab(self.settings_tab, "Settings")
        
        self.setup_scan_tab()
        self.setup_settings_tab()
        
        layout.addWidget(self.tabs)
        
    def setup_scan_tab(self):
        layout = QVBoxLayout(self.scan_tab)
        
        # Selection group
        selection_group = QGroupBox("Select Scan Type")
        selection_layout = QHBoxLayout()
        
        self.ip_radio = QRadioButton("IP Address")
        self.ip_radio.setChecked(True)
        self.file_radio = QRadioButton("File Upload")
        
        selection_layout.addWidget(self.ip_radio)
        selection_layout.addWidget(self.file_radio)
        selection_group.setLayout(selection_layout)
        
        layout.addWidget(selection_group)
        
        # IP input section
        ip_group = QGroupBox("IP Address Scan")
        ip_layout = QVBoxLayout()
        
        ip_form_layout = QFormLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP address")
        ip_form_layout.addRow("IP Address:", self.ip_input)
        
        ip_layout.addLayout(ip_form_layout)
        
        self.ip_scan_btn = QPushButton("Scan IP")
        self.ip_scan_btn.clicked.connect(self.scan_ip)
        ip_layout.addWidget(self.ip_scan_btn)
        
        ip_group.setLayout(ip_layout)
        layout.addWidget(ip_group)
        
        # File upload section
        file_group = QGroupBox("File Scan")
        file_layout = QVBoxLayout()
        
        file_form_layout = QFormLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setReadOnly(True)
        file_form_layout.addRow("File Path:", self.file_path_input)
        
        file_layout.addLayout(file_form_layout)
        
        file_btn_layout = QHBoxLayout()
        self.file_browse_btn = QPushButton("Browse")
        self.file_browse_btn.clicked.connect(self.browse_file)
        self.file_scan_btn = QPushButton("Scan File")
        self.file_scan_btn.clicked.connect(self.scan_file)
        
        file_btn_layout.addWidget(self.file_browse_btn)
        file_btn_layout.addWidget(self.file_scan_btn)
        file_layout.addLayout(file_btn_layout)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Results section
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        results_layout.addWidget(self.results_text)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Connect radio buttons to toggle visibility
        self.ip_radio.toggled.connect(self.toggle_scan_type)
        self.file_radio.toggled.connect(self.toggle_scan_type)
        self.toggle_scan_type()
        
    def setup_settings_tab(self):
        layout = QVBoxLayout(self.settings_tab)
        
        # API keys form
        form_layout = QFormLayout()
        
        self.abuseipdb_key_input = QLineEdit()
        self.abuseipdb_key_input.setEchoMode(QLineEdit.Password)
        form_layout.addRow("AbuseIPDB API Key:", self.abuseipdb_key_input)
        
        self.virustotal_key_input = QLineEdit()
        self.virustotal_key_input.setEchoMode(QLineEdit.Password)
        form_layout.addRow("VirusTotal API Key:", self.virustotal_key_input)
        
        layout.addLayout(form_layout)
        
        # Save button
        self.save_settings_btn = QPushButton("Save Settings")
        self.save_settings_btn.clicked.connect(self.save_settings)
        layout.addWidget(self.save_settings_btn)
        
        # Add stretch to push everything to the top
        layout.addStretch()
        
    def toggle_scan_type(self):
        ip_selected = self.ip_radio.isChecked()
        
        # Find the group boxes by their titles
        for i in range(self.scan_tab.layout().count()):
            widget = self.scan_tab.layout().itemAt(i).widget()
            if isinstance(widget, QGroupBox):
                if widget.title() == "IP Address Scan":
                    widget.setVisible(ip_selected)
                elif widget.title() == "File Scan":
                    widget.setVisible(not ip_selected)
        
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path_input.setText(file_path)
            
    def scan_ip(self):
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Input Error", "Please enter an IP address")
            return
            
        self.results_text.clear()
        self.results_text.append(f"Scanning IP: {ip}")
        self.results_text.append("=" * 50)
        
        # Get API keys from settings
        abuseipdb_key = self.abuseipdb_key_input.text().strip()
        virustotal_key = self.virustotal_key_input.text().strip()
        
        if not abuseipdb_key or not virustotal_key:
            QMessageBox.warning(self, "API Error", "Please set both API keys in the Settings tab")
            return
            
        # Scan with AbuseIPDB
        self.results_text.append("\nAbuseIPDB Results:")
        self.results_text.append("-" * 30)
        abuse_result = self.scan_abuseipdb(ip, abuseipdb_key)
        self.results_text.append(abuse_result)
        
        # Scan with VirusTotal
        self.results_text.append("\nVirusTotal Results:")
        self.results_text.append("-" * 30)
        vt_result = self.scan_virustotal_ip(ip, virustotal_key)
        self.results_text.append(vt_result)
        
    def scan_file(self):
        file_path = self.file_path_input.text().strip()
        if not file_path:
            QMessageBox.warning(self, "Input Error", "Please select a file")
            return
            
        self.results_text.clear()
        self.results_text.append(f"Scanning File: {file_path}")
        self.results_text.append("=" * 50)
        
        # Get API key from settings
        virustotal_key = self.virustotal_key_input.text().strip()
        
        if not virustotal_key:
            QMessageBox.warning(self, "API Error", "Please set the VirusTotal API key in the Settings tab")
            return
            
        # Calculate file hash
        try:
            file_hash = self.calculate_file_hash(file_path)
            self.results_text.append(f"File Hash (SHA-256): {file_hash}")
            
            # Scan with VirusTotal
            self.results_text.append("\nVirusTotal Results:")
            self.results_text.append("-" * 30)
            vt_result = self.scan_virustotal_file(file_hash, virustotal_key)
            self.results_text.append(vt_result)
            
        except Exception as e:
            self.results_text.append(f"Error: {str(e)}")
            
    def calculate_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
        
    def scan_abuseipdb(self, ip, api_key):
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            querystring = {
                'ipAddress': ip,
                'maxAgeInDays': '90'
            }
            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }
            
            response = requests.request(method='GET', url=url, headers=headers, params=querystring)
            data = response.json()
            
            if 'data' in data:
                result = f"IP: {data['data']['ipAddress']}\n"
                result += f"Abuse Confidence Score: {data['data']['abuseConfidenceScore']}%\n"
                result += f"Country: {data['data']['countryCode']} ({data['data']['countryName']})\n"
                result += f"ISP: {data['data']['isp']}\n"
                result += f"Domain: {data['data'].get('domain', 'N/A')}\n"
                result += f"Total Reports: {data['data']['totalReports']}\n"
                result += f"Distinct Users: {data['data']['numDistinctUsers']}\n"
                result += f"Last Reported: {data['data']['lastReportedAt']}\n"
                
                # Determine threat level
                confidence = data['data']['abuseConfidenceScore']
                if confidence >= 75:
                    threat_level = "HIGH"
                elif confidence >= 25:
                    threat_level = "MEDIUM"
                else:
                    threat_level = "LOW"
                    
                result += f"\nThreat Level: {threat_level}"
                return result
            else:
                return f"Error: {data.get('errors', 'Unknown error')}"
                
        except Exception as e:
            return f"Error scanning with AbuseIPDB: {str(e)}"
            
    def scan_virustotal_ip(self, ip, api_key):
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }
            
            response = requests.get(url, headers=headers)
            data = response.json()
            
            if 'data' in data and 'attributes' in data['data']:
                attrs = data['data']['attributes']
                stats = attrs.get('last_analysis_stats', {})
                
                result = f"IP: {data['data']['id']}\n"
                result += f"Reputation: {attrs.get('reputation', 'N/A')}\n"
                result += f"ASN: {attrs.get('asn', 'N/A')}\n"
                result += f"AS Owner: {attrs.get('as_owner', 'N/A')}\n"
                result += f"Country: {attrs.get('country', 'N/A')}\n"
                result += f"Analysis Stats:\n"
                result += f"  Malicious: {stats.get('malicious', 0)}\n"
                result += f"  Suspicious: {stats.get('suspicious', 0)}\n"
                result += f"  Undetected: {stats.get('undetected', 0)}\n"
                result += f"  Harmless: {stats.get('harmless', 0)}\n"
                
                # Determine threat level based on malicious count
                malicious = stats.get('malicious', 0)
                if malicious > 5:
                    threat_level = "HIGH"
                elif malicious > 1:
                    threat_level = "MEDIUM"
                elif malicious == 1:
                    threat_level = "LOW"
                else:
                    threat_level = "CLEAN"
                    
                result += f"\nThreat Level: {threat_level}"
                return result
            else:
                return f"Error: {data.get('error', 'Unknown error')}"
                
        except Exception as e:
            return f"Error scanning with VirusTotal: {str(e)}"
            
    def scan_virustotal_file(self, file_hash, api_key):
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }
            
            response = requests.get(url, headers=headers)
            data = response.json()
            
            if 'data' in data and 'attributes' in data['data']:
                attrs = data['data']['attributes']
                stats = attrs.get('last_analysis_stats', {})
                
                result = f"File: {data['data']['id']}\n"
                result += f"Type: {attrs.get('type_description', 'N/A')}\n"
                result += f"Size: {attrs.get('size', 'N/A')} bytes\n"
                result += f"First Submission: {attrs.get('first_submission_date', 'N/A')}\n"
                result += f"Last Analysis: {attrs.get('last_analysis_date', 'N/A')}\n"
                result += f"Analysis Stats:\n"
                result += f"  Malicious: {stats.get('malicious', 0)}\n"
                result += f"  Suspicious: {stats.get('suspicious', 0)}\n"
                result += f"  Undetected: {stats.get('undetected', 0)}\n"
                result += f"  Harmless: {stats.get('harmless', 0)}\n"
                
                # Determine threat level based on malicious count
                malicious = stats.get('malicious', 0)
                if malicious > 10:
                    threat_level = "HIGH"
                elif malicious > 3:
                    threat_level = "MEDIUM"
                elif malicious > 0:
                    threat_level = "LOW"
                else:
                    threat_level = "CLEAN"
                    
                result += f"\nThreat Level: {threat_level}"
                
                # Add popular threat classification if available
                if 'popular_threat_classification' in attrs:
                    threat_class = attrs['popular_threat_classification']
                    if 'suggested_threat_label' in threat_class:
                        result += f"\nSuggested Threat: {threat_class['suggested_threat_label']}"
                
                return result
            else:
                return f"Error: {data.get('error', 'Unknown error')}"
                
        except Exception as e:
            return f"Error scanning with VirusTotal: {str(e)}"
            
    def load_settings(self):
        # In a real application, you would load these from a config file
        # For now, we'll set the default values you provided
        self.abuseipdb_key_input.setText("fcab3a321d5debbab5b6f8fd32bf7847a9de868935f42daae14403a951c5490f3e6c7bd3ed630a3c")
        self.virustotal_key_input.setText("06e809ecf15d400ac95f5376765eff953e4225c0846d83a795fcb1b669d674c2")
        
    def save_settings(self):
        # In a real application, you would save these to a config file
        QMessageBox.information(self, "Settings Saved", "API keys have been saved successfully!")
        
def main():
    app = QApplication(sys.argv)
    window = ThreatIntelligenceApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
