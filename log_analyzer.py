import sys
import re
from datetime import datetime
from collections import defaultdict
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox, 
                             QDateTimeEdit, QCheckBox, QDialog, QListWidget, QFileDialog,
                             QGridLayout, QGroupBox, QSplitter, QStyleFactory)
from PyQt6.QtCore import Qt, QDateTime
from PyQt6.QtGui import QIcon, QFont

class LogAnalyzer:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.logs = self.parse_logs()
        self.torrent_users = self.find_torrent_users()

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
                            'email': email if email else 'N/A',
                            'uses_torrent': 'torrent' in routing.lower()  # Теперь ищем слово "torrent"
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

    def get_torrent_logs_for_email(self, email):
        """Возвращает список логов использования торрентов для данного клиента."""
        return [log for log in self.logs if log['email'] == email and log['uses_torrent']]

    def find_torrent_users(self):
        return set(log['email'] for log in self.logs if log['uses_torrent'])

    def filter_logs(self, email=None, site=None, exclude_site=None, start_time=None, end_time=None):
        filtered_logs = self.logs
        if email:
            filtered_logs = [log for log in filtered_logs if log['email'] == email]
        if site:
            filtered_logs = [log for log in filtered_logs if site.lower() in log['connection'].lower()]
        if exclude_site:
            filtered_logs = [log for log in filtered_logs if exclude_site.lower() not in log['connection'].lower()]
        if start_time:
            filtered_logs = [log for log in filtered_logs if log['timestamp'] >= start_time]
        if end_time:
            filtered_logs = [log for log in filtered_logs if log['timestamp'] <= end_time]
        return filtered_logs

    def get_unique_domain_logs(self, logs):
        unique_domains = set()
        filtered_logs = []
        for log in logs:
            domain = self.get_main_domain(log['connection'])
            if domain not in unique_domains:
                unique_domains.add(domain)
                filtered_logs.append(log)
        return filtered_logs

    @staticmethod
    def get_main_domain(connection):
        match = re.search(r'(\d+\.\d+\.\d+\.\d+|[\w\.-]+\.[a-z]{2,6})', connection)
        return match.group(0) if match else 'Unknown'

class TorrentUsageDialog(QDialog):
    def __init__(self, torrent_logs, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Использование торрентов")
        self.setGeometry(200, 200, 400, 300)
        
        layout = QVBoxLayout()
        self.log_list_widget = QListWidget()
        
        for log in torrent_logs:
            item_text = f"{log['timestamp']} - {log['connection']}"
            self.log_list_widget.addItem(item_text)
        
        layout.addWidget(self.log_list_widget)
        self.setLayout(layout)

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
        main_layout = QVBoxLayout(central_widget)

        # Создаем разделитель для верхней и нижней части интерфейса
        splitter = QSplitter(Qt.Orientation.Vertical)
        main_layout.addWidget(splitter)

        # Верхняя часть интерфейса
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        splitter.addWidget(top_widget)

        # Группа выбора файла и клиента
        file_client_group = QGroupBox("Файл и клиент")
        file_client_layout = QGridLayout()

        self.file_button = QPushButton('Выбрать файл')
        self.file_button.setIcon(QIcon.fromTheme("document-open"))
        self.file_button.clicked.connect(self.choose_file)
        file_client_layout.addWidget(self.file_button, 0, 0)

        self.file_label = QLabel('Файл не выбран')
        file_client_layout.addWidget(self.file_label, 0, 1, 1, 2)

        file_client_layout.addWidget(QLabel('Клиент:'), 1, 0)
        self.client_combo = QComboBox()
        file_client_layout.addWidget(self.client_combo, 1, 1)

        self.show_ip_button = QPushButton('Показать IP клиента')
        self.show_ip_button.clicked.connect(self.show_ip_list)
        file_client_layout.addWidget(self.show_ip_button, 1, 2)

        self.torrent_label = QLabel('')
        file_client_layout.addWidget(self.torrent_label, 1, 3)

        self.show_torrent_button = QPushButton('Показать торренты')
        self.show_torrent_button.clicked.connect(self.show_torrent_usage)
        file_client_layout.addWidget(self.show_torrent_button, 1, 4)

        file_client_group.setLayout(file_client_layout)
        top_layout.addWidget(file_client_group)

        # Группа фильтров
        filter_group = QGroupBox("Фильтры")
        filter_layout = QGridLayout()

        filter_layout.addWidget(QLabel('Поиск по сайту:'), 0, 0)
        self.site_input = QLineEdit()
        filter_layout.addWidget(self.site_input, 0, 1)

        filter_layout.addWidget(QLabel('Исключить сайт:'), 0, 2)
        self.exclude_site_input = QLineEdit()
        filter_layout.addWidget(self.exclude_site_input, 0, 3)

        filter_layout.addWidget(QLabel('Начало:'), 1, 0)
        self.start_time = QDateTimeEdit(QDateTime.currentDateTime().addDays(-1))
        filter_layout.addWidget(self.start_time, 1, 1)

        filter_layout.addWidget(QLabel('Конец:'), 1, 2)
        self.end_time = QDateTimeEdit(QDateTime.currentDateTime())
        filter_layout.addWidget(self.end_time, 1, 3)

        self.unique_domains_checkbox = QCheckBox('Только уникальные домены')
        filter_layout.addWidget(self.unique_domains_checkbox, 2, 0, 1, 2)

        self.toggle_ip_button = QPushButton('Скрыть IP из поиска')
        self.toggle_ip_button.clicked.connect(self.toggle_ip_visibility)
        filter_layout.addWidget(self.toggle_ip_button, 2, 2)

        self.search_button = QPushButton('Поиск')
        self.search_button.setIcon(QIcon.fromTheme("search"))
        self.search_button.clicked.connect(self.search_logs)
        filter_layout.addWidget(self.search_button, 2, 3)

        filter_group.setLayout(filter_layout)
        top_layout.addWidget(filter_group)

        # Нижняя часть интерфейса
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        splitter.addWidget(bottom_widget)

        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        bottom_layout.addWidget(self.results_area)

        # Устанавливаем шрифт
        font = QFont("Courier")
        font.setPointSize(10)
        self.results_area.setFont(font)

        # Применяем стиль Fusion для более современного вида
        QApplication.setStyle(QStyleFactory.create('Fusion'))

    def choose_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Выберите файл логов", "", "Log Files (*.log);;All Files (*)")
        if file_name:
            self.file_label.setText(file_name)
            self.log_analyzer = LogAnalyzer(file_name)
            self.update_client_list()

    def update_client_list(self):
        self.client_combo.clear()
        self.client_combo.addItems(['Все'] + self.log_analyzer.get_unique_emails())
        self.client_combo.currentIndexChanged.connect(self.update_torrent_label)

    def update_torrent_label(self):
        if self.log_analyzer and self.client_combo.currentText() != 'Все':
            uses_torrent = self.client_combo.currentText() in self.log_analyzer.torrent_users
            self.torrent_label.setText('Использует торренты' if uses_torrent else 'Не использует торренты')
            self.show_torrent_button.setEnabled(uses_torrent)  # Активируем кнопку только если клиент использует торренты
        else:
            self.torrent_label.setText('')
            self.show_torrent_button.setEnabled(False)

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
            result_text += f"{log['timestamp']} - {main_domain}\n"

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

    def show_torrent_usage(self):
        """Открывает диалог с логами использования торрентов для выбранного клиента."""
        if not self.log_analyzer:
            self.results_area.setText("Пожалуйста, выберите файл логов.")
            return

        email = self.client_combo.currentText()
        if email != 'Все':
            torrent_logs = self.log_analyzer.get_torrent_logs_for_email(email)
            if torrent_logs:
                dialog = TorrentUsageDialog(torrent_logs, self)
                dialog.exec()
            else:
                self.results_area.setText("У данного клиента нет записей использования торрентов.")
        else:
            self.results_area.setText("Пожалуйста, выберите конкретного клиента для просмотра использования торрентов.")

    def toggle_ip_visibility(self):
        self.hide_ip = not self.hide_ip
        self.toggle_ip_button.setText('Показать IP в поиске' if self.hide_ip else 'Скрыть IP из поиска')
        self.search_logs()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setApplicationName('KoPobka Analizator')
    ex = LogAnalyzerGUI()
    ex.show()
    sys.exit(app.exec())
