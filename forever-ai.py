import os
import hashlib
import json
import psutil
import time
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import QMessageBox, QVBoxLayout, QPushButton, QLabel, QLineEdit, QTextEdit, QWidget, QHBoxLayout, QStatusBar, QComboBox, QSystemTrayIcon, QMenu, QAction, QDialog, QListWidget, QTableWidget, QTableWidgetItem, QDialogButtonBox, QFileDialog
import sys
import requests

class MonitoringThread(QtCore.QThread):
    update_signal = QtCore.pyqtSignal(str)  # Signal to update the GUI

    def __init__(self, antivirus):
        super().__init__()
        self.antivirus = antivirus
        self.running = True

    def run(self):
        while self.running:
            for root, _, files in os.walk("C:/"):  # Monitor the C drive (or any specified path)
                for file in files:
                    file_path = os.path.join(root, file)
                    is_infected, hash_val = self.antivirus.scan_file(file_path)
                    if is_infected:
                        self.antivirus.quarantine_file(file_path)
                        self.update_signal.emit(f"Quarantined: {file_path}")
            time.sleep(10)  # Check every 10 seconds

    def stop(self):
        self.running = False

class ForeverAI:
    def __init__(self):
        self.vt_api_key = "c86727aa3ed1f19a6db36289f2879e865b191cfce95689d38da1c2491584a91f"  # Замените на ваш фактический API-ключ
        self.signature_db = "virus_signatures.json"
        self.load_signatures()
        self.quarantine_folder = "quarantine"
        os.makedirs(self.quarantine_folder, exist_ok=True)

    def load_signatures(self):
        if not os.path.exists(self.signature_db):
            self.signatures = {"md5": [], "sha256": []}
            self.save_signatures()
        else:
            with open(self.signature_db, "r") as f:
                self.signatures = json.load(f)

    def save_signatures(self):
        with open(self.signature_db, "w") as f:
            json.dump(self.signatures, f)

    def update_signatures(self):
        print("[+] Checking for updates...")
        self.load_signatures()
        print("[+] Signature database updated!")

    def calculate_hash(self, file_path, algorithm="md5"):
        try:
            hasher = hashlib.md5() if algorithm == "md5" else hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            print(f"Error calculating hash: {e}")
            return None

    def scan_file(self, file_path):
        if not os.path.isfile(file_path):
            return False, None
        
        try:
            md5_hash = self.calculate_hash(file_path, "md5")
            sha_hash = self.calculate_hash(file_path, "sha256")
        except Exception as e:
            return False, None
        
        if md5_hash in self.signatures["md5"]:
            return True, md5_hash
        if sha_hash in self.signatures["sha256"]:
            return True, sha_hash
        
        return False, None

    def scan_directory(self, path):
        infected_files = []
        for root, _, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                is_infected, hash_val = self.scan_file(file_path)
                if is_infected:
                    infected_files.append((file_path, hash_val, "Local Scanner"))
                else:
                    vt_result = self.scan_file_vt(file_path)
                    if vt_result:
                        infected_files.append((file_path, vt_result, "VirusTotal"))
        return infected_files

    def scan_processes(self):
        infected_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['exe']:
                    is_infected, hash_val = self.scan_file(proc.info['exe'])
                    if is_infected:
                        infected_processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
                continue
        return infected_processes

    def quarantine_file(self, file_path):
        try:
            os.rename(file_path, os.path.join(self.quarantine_folder, os.path.basename(file_path)))
            return True
        except Exception as e:
            print(f"Error quarantining file {file_path}: {e}")
            return False

    def delete_file(self, file_path):
        try:
            # Secure file deletion implementation
            with open(file_path, "ba+") as f:
                length = f.tell()
                for _ in range(3):  # Overwrite 3 times
                    f.seek(0)
                    f.write(os.urandom(length))
                f.truncate()
            os.remove(file_path)
            return True
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")
            return False

    def scan_file_vt(self, file_path):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': self.vt_api_key}
        files = {'file': open(file_path, 'rb')}
        response = requests.post(url, files=files, params=params)
        
        if response.status_code == 200:
            json_response = response.json()
            permalink = json_response['permalink']
            # Дополнительная обработка ответа VirusTotal, если необходимо
            return permalink
        else:
            print(f"VirusTotal scan request failed with status code {response.status_code}")
            return None

class VirusListDialog(QDialog):
    def __init__(self, infected_files, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Найденные вирусы")
        self.setGeometry(100, 100, 600, 400)
        
        layout = QVBoxLayout()
        
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Файл", "Хэш"])
        self.table.horizontalHeader().setStretchLastSection(True)
        
        for file_path, hash_val in infected_files:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(file_path))
            self.table.setItem(row, 1, QTableWidgetItem(hash_val))
        
        layout.addWidget(self.table)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(self.accept)
        layout.addWidget(button_box)
        
        self.setLayout(layout)

class AntivirusApp(QWidget):
    def __init__(self):
        super().__init__()
        self.antivirus = ForeverAI()
        self.monitoring_thread = None
        self.initUI()
        self.create_tray_icon()

    def initUI(self):
        self.setWindowTitle('FOREVER AI Antivirus')
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("""
            QWidget {
                background-color: #f0f0f0;
                font-family: Arial;
                color: #333;
            }
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #333;
                padding: 10px;
            }
            QPushButton {
                background-color: #007bff;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 4px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QTextEdit {
                background-color: white;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 14px;
                padding: 10px;
            }
        """)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)

        header = QLabel('FOREVER AI Antivirus')
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #333;
            padding: 20px;
            background-color: #fff;
            border-radius: 4px;
            border: 1px solid #ccc;
        """)
        main_layout.addWidget(header)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        self.scan_file_button = QPushButton('Сканировать файл', self)
        self.scan_file_button.clicked.connect(self.scan_file)
        button_layout.addWidget(self.scan_file_button)

        self.scan_directory_button = QPushButton('Сканировать папку', self)
        self.scan_directory_button.clicked.connect(self.scan_directory)
        button_layout.addWidget(self.scan_directory_button)

        main_layout.addLayout(button_layout)

        button_layout2 = QHBoxLayout()
        button_layout2.setSpacing(10)

        self.update_button = QPushButton('Обновить сигнатуры', self)
        self.update_button.clicked.connect(self.update_signatures)
        button_layout2.addWidget(self.update_button)

        self.monitor_button = QPushButton('Запустить мониторинг', self)
        self.monitor_button.clicked.connect(self.start_monitoring)
        button_layout2.addWidget(self.monitor_button)

        self.stop_monitor_button = QPushButton('Остановить мониторинг', self)
        self.stop_monitor_button.clicked.connect(self.stop_monitoring)
        button_layout2.addWidget(self.stop_monitor_button)

        main_layout.addLayout(button_layout2)

        self.results_area = QTextEdit(self)
        self.results_area.setReadOnly(True)
        main_layout.addWidget(self.results_area)

        self.setLayout(main_layout)

    def create_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QtGui.QIcon("icon.png"))  # Замените "icon.png" на путь к вашей иконке
        self.tray_icon.setVisible(True)

        self.tray_menu = QMenu(self)
        self.tray_menu.addAction("Открыть", self.show)
        self.tray_menu.addAction("Выход", QtWidgets.qApp.quit)
        self.tray_icon.setContextMenu(self.tray_menu)

    def start_monitoring(self):
        if not self.monitoring_thread or not self.monitoring_thread.isRunning():
            self.monitoring_thread = MonitoringThread(self.antivirus)
            self.monitoring_thread.update_signal.connect(self.update_results)
            self.monitoring_thread.start()

    def stop_monitoring(self):
        if self.monitoring_thread and self.monitoring_thread.isRunning():
            self.monitoring_thread.stop()
            self.monitoring_thread.wait()

    def update_signatures(self):
        self.antivirus.update_signatures()

    def scan_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл", "", "Все файлы (*)")
        if file_path:
            is_infected, hash_val = self.antivirus.scan_file(file_path)
            if is_infected:
                self.results_area.append(f"Файл {file_path} заражен. Хэш: {hash_val}")
            else:
                self.results_area.append(f"Файл {file_path} безопасен.")

    def scan_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Выберите папку", "")
        if directory:
            infected_files = self.antivirus.scan_directory(directory)
            if infected_files:
                self.results_area.append(f"Найдено {len(infected_files)} зараженных файлов.")
                dialog = VirusListDialog(infected_files, self)
                dialog.exec_()
            else:
                self.results_area.append("Зараженные файлы не найдены.")

    def update_results(self, message):
        self.results_area.append(message)

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = AntivirusApp()
    window.show()
    sys.exit(app.exec_())