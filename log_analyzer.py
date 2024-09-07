import sys
import re
from datetime import datetime
from collections import defaultdict
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox, 
                             QDateTimeEdit, QCheckBox, QDialog, QListWidget, QFileDialog)
from PyQt6.QtCore import Qt, QDateTime
from PyQt6.QtGui import QIcon

class LogAnalyzer:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.logs = self.parse_logs()

    def parse_logs(self):
        log_pattern = re.compile(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) (.*?) accepted (.*?) \[(.*?)\] (?:email: (.*))?')
        parsed_logs = []
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as file:
                for line in file:
                    match = log_pattern.match(line.strip())
                    if match:
                        timestamp, ip, connection, routing, email = match.groups()
                        parsed_logs.append({
                            'timestamp': datetime.strptime(timestamp, '%Y/%m/%d %H:%M:%S'),
                            'ip': self.clean_ip(ip),
                            'connection': connection,
                            'routing': routing,
                            'email': email if email else 'N/A'
                        })
        except Exception as e:
            print(f"Произошла ошибка при чтении файла: {e}")
        return parsed_logs

    @staticmethod
    def clean_ip(ip):
        return re.sub(r'(from )?(tcp:)?(udp:)?(\d+\.\d+\.\d+\.\d+).*', r'\4', ip)

    def get_unique_emails(self):
        return sorted(set(log['email'] for log in self.logs))

    def get_unique_ips(self, email):
        return sorted(set(log['ip'] for log in self.logs if log['email'] == email))

    def filter_logs(self, email=None, site=None, exclude_site=None, start_time=None, end_time=None):
        filtered_logs = self.logs
        if email:
            filtered_logs = [log for log in filtered_logs if log['email'] == email]
        if site:
            filtered_logs = [log for log in filtered_logs if site.lower() in self.get_main_domain(log['connection']).lower()]
        if exclude_site:
            filtered_logs = [log for log in filtered_logs if exclude_site.lower() not in self.get_main_domain(log['connection']).lower()]
        if start_time:
            filtered_logs = [log for log in filtered_logs if log['timestamp'] >= start_time]
        if end_time:
            filtered_logs = [log for log in filtered_logs if log['timestamp'] <= end_time]
        return filtered_logs

    @staticmethod
    def get_main_domain(connection):
        connection = re.sub(r'^(tcp:|udp:)', '', connection)
        domain = connection.split(':')[0]
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            return domain  # Это IP-адрес
        parts = domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        return domain

    def get_unique_domain_logs(self, logs):
        unique_logs = defaultdict(dict)
        for log in logs:
            email = log['email']
            domain = self.get_main_domain(log['connection'])
            if domain not in unique_logs[email]:
                unique_logs[email][domain] = log
        return [log for email_logs in unique_logs.values() for log in email_logs.values()]

class IPListDialog(QDialog):
    def __init__(self, ip_list, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Список IP-адресов")
        self.setGeometry(200, 200, 300, 400)
        layout = QVBoxLayout()
        self.ip_list_widget = QListWidget()
        self.ip_list_widget.addItems(ip_list)
        layout.addWidget(self.ip_list_widget)
        self.setLayout(layout)

class LogAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.log_analyzer = None
        self.hide_ip = False
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('KoPobka Analizator')
        self.setGeometry(100, 100, 800, 600)


        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        file_layout = QHBoxLayout()
        self.file_button = QPushButton('Выбрать файл логов')
        self.file_button.clicked.connect(self.choose_file)
        file_layout.addWidget(self.file_button)
        self.file_label = QLabel('Файл не выбран')
        file_layout.addWidget(self.file_label)
        layout.addLayout(file_layout)

        client_layout = QHBoxLayout()
        client_layout.addWidget(QLabel('Выберите клиента:'))
        self.client_combo = QComboBox()
        client_layout.addWidget(self.client_combo)
        self.show_ip_button = QPushButton('Показать IP')
        self.show_ip_button.clicked.connect(self.show_ip_list)
        client_layout.addWidget(self.show_ip_button)
        layout.addLayout(client_layout)

        site_layout = QHBoxLayout()
        site_layout.addWidget(QLabel('Поиск по сайту:'))
        self.site_input = QLineEdit()
        site_layout.addWidget(self.site_input)
        self.search_button = QPushButton('Поиск')
        self.search_button.clicked.connect(self.search_logs)
        site_layout.addWidget(self.search_button)
        layout.addLayout(site_layout)

        exclude_site_layout = QHBoxLayout()
        exclude_site_layout.addWidget(QLabel('Исключить сайт:'))
        self.exclude_site_input = QLineEdit()
        exclude_site_layout.addWidget(self.exclude_site_input)
        layout.addLayout(exclude_site_layout)

        time_layout = QHBoxLayout()
        time_layout.addWidget(QLabel('Начало:'))
        self.start_time = QDateTimeEdit(QDateTime.currentDateTime().addDays(-1))
        time_layout.addWidget(self.start_time)
        time_layout.addWidget(QLabel('Конец:'))
        self.end_time = QDateTimeEdit(QDateTime.currentDateTime())
        time_layout.addWidget(self.end_time)
        layout.addLayout(time_layout)

        self.unique_domains_checkbox = QCheckBox('Показывать только уникальные домены')
        layout.addWidget(self.unique_domains_checkbox)

        self.toggle_ip_button = QPushButton('Скрыть IP')
        self.toggle_ip_button.clicked.connect(self.toggle_ip_visibility)
        layout.addWidget(self.toggle_ip_button)

        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        layout.addWidget(self.results_area)

    def choose_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Выберите файл логов", "", "Log Files (*.log);;All Files (*)")
        if file_name:
            self.file_label.setText(file_name)
            self.log_analyzer = LogAnalyzer(file_name)
            self.update_client_list()

    def update_client_list(self):
        self.client_combo.clear()
        self.client_combo.addItems(['Все'] + self.log_analyzer.get_unique_emails())

    def search_logs(self):
        if not self.log_analyzer:
            self.results_area.setText("Пожалуйста, выберите файл логов.")
            return

        email = self.client_combo.currentText()
        email = email if email != 'Все' else None
        site = self.site_input.text()
        exclude_site = self.exclude_site_input.text()
        start_time = self.start_time.dateTime().toPyDateTime()
        end_time = self.end_time.dateTime().toPyDateTime()

        filtered_logs = self.log_analyzer.filter_logs(email, site, exclude_site, start_time, end_time)

        if self.unique_domains_checkbox.isChecked():
            filtered_logs = self.log_analyzer.get_unique_domain_logs(filtered_logs)

        result_text = f"Найдено записей: {len(filtered_logs)}\n\n"
        for log in filtered_logs:
            main_domain = self.log_analyzer.get_main_domain(log['connection'])
            if self.hide_ip and re.match(r'\d+\.\d+\.\d+\.\d+', main_domain):
                continue  # Пропускаем записи с IP-адресами, если hide_ip=True
            result_text += f"{log['timestamp']} - {log['email']} - {main_domain}\n"

        self.results_area.setText(result_text)

    def show_ip_list(self):
        if not self.log_analyzer:
            self.results_area.setText("Пожалуйста, выберите файл логов.")
            return

        email = self.client_combo.currentText()
        if email != 'Все':
            ip_list = self.log_analyzer.get_unique_ips(email)
            dialog = IPListDialog(ip_list, self)
            dialog.exec()
        else:
            self.results_area.setText("Пожалуйста, выберите конкретного клиента для просмотра IP-адресов.")

    def toggle_ip_visibility(self):
        self.hide_ip = not self.hide_ip
        self.toggle_ip_button.setText('Показать IP' if self.hide_ip else 'Скрыть IP')
        self.search_logs()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setApplicationName('KoPobkaAnalizator')
    ex = LogAnalyzerGUI()
    ex.show()
    sys.exit(app.exec())
