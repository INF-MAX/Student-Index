import sys
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QMessageBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QComboBox, QDialog, QFormLayout, QDialogButtonBox,
    QSpinBox, QTabWidget, QListWidget, QStackedWidget
)
from PyQt5.QtGui import QFont, QColor, QPalette
from PyQt5.QtCore import Qt

# 全局样式配置（精简版）
STYLE_SHEET = """
    QMainWindow { background-color: #f5f6fa; }
    QLabel { font-size: 14px; color: #2d3436; }
    QLineEdit, QComboBox { 
        padding: 8px; border: 1px solid #dcdde1; 
        border-radius: 4px; background: white;
    }
    QPushButton {
        padding: 10px 20px; background: #00a8ff;
        color: white; border-radius: 4px;
    }
    QPushButton:hover { background: #0097e6; }
    QTableWidget { 
        gridline-color: #dcdde1; 
        alternate-background-color: #f8f9fa; 
    }
"""

# 加密配置（建议改为从环境变量读取）
SECRET_KEY = b'YourSecretKey123'  # 16 bytes
IV = b'InitializationVe'         # 16 bytes

# ------------------------- 数据模型类 -------------------------
class User:
    def __init__(self, username, password_hash, role):
        self.username = username
        self.password_hash = password_hash
        self.role = role

    def verify_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest() == self.password_hash

class Student:
    def __init__(self, name, password_hash, scores, rank, grade):
        self.name = name
        self.password_hash = password_hash
        self.scores = scores
        self.rank = rank
        self.grade = grade

    def verify_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest() == self.password_hash

class DataManager:
    @staticmethod
    def load_data(filename):
        try:
            with open(filename, 'rb') as f:
                encrypted_data = f.read()
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            QMessageBox.critical(None, "错误", f"数据加载失败: {str(e)}")
            return {}

    @staticmethod
    def save_data(data, filename):
        try:
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
            encrypted_data = cipher.encrypt(pad(json.dumps(data).encode(), AES.block_size))
            with open(filename, 'wb') as f:
                f.write(encrypted_data)
            return True
        except Exception as e:
            QMessageBox.critical(None, "错误", f"数据保存失败: {str(e)}")
            return False

# ------------------------- 界面类 -------------------------
class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("学生成绩管理系统 - 登录")
        self.setFixedSize(400, 400)
        self.init_ui()
        self.load_initial_data()

    def init_ui(self):
        # ...（与原始代码一致，略）...

    def load_initial_data(self):
        self.grade_data = DataManager.load_data('grade_1.enc') or {}
        self.teacher_users = [
            User("admin", hashlib.sha256("admin123".encode()).hexdigest(), "teacher")
        ]

    def verify_login(self):
        # ...（改进：增加空输入校验）...
        if not username or not password:
            QMessageBox.warning(self, "错误", "用户名或密码不能为空！")
            return
        # ...（其余逻辑与原始代码一致）...

class StudentWindow(QMainWindow):
    def __init__(self, student):
        super().__init__()
        self.student = student
        self.init_ui()

    def init_ui(self):
        # ...（优化表格排序和颜色标记）...
        for i, (subject, score) in enumerate(sorted_scores):
            color = QColor("#e74c3c") if score < 60 else QColor("#2ecc71")
            score_item.setForeground(color)

class TeacherWindow(QMainWindow):
    def __init__(self, grade_data):
        super().__init__()
        self.grade_data = grade_data
        self.init_ui()

    def init_ui(self):
        # ...（新增功能：自动计算排名）...
        self.calculate_rank()

    def calculate_rank(self):
        students = self.grade_data.get('students', [])
        sorted_students = sorted(students, key=lambda x: sum(x['scores'].values()), reverse=True)
        for idx, student in enumerate(sorted_students):
            student['rank'] = idx + 1

    def save_score(self):
        # ...（增加分数范围校验）...
        if not 0 <= score <= 100:
            QMessageBox.warning(self, "错误", "成绩必须在0-100之间！")
            return

# ------------------------- 主程序入口 -------------------------
def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE_SHEET)
    login_window = LoginWindow()
    login_window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

