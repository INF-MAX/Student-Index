#加密机制
#使用 AES-CBC 模式加密数据，密钥 (SECRET_KEY) 和初始化向量 (IV) 硬编码在代码中。
#GradeFile 类提供 encrypt_data 和 decrypt_data 方法，实现数据加密保存为 .enc 文件和解密读取功能。

#用户角色与权限
#学生：通过 StudentWindow 查看个人成绩、排名及年级信息。
#教师：通过 TeacherWindow 管理学生信息（增删改查）、录入成绩、生成加密文件。

#数据存储结构
#数据以 ENC 格式存储，包含加密后的grade（年级）和 students（学生列表）。
#学生信息包括 name（姓名）、password_hash（密码哈希）、scores（科目成绩字典）、rank（年级排名）。

#GUI 框架
#基于 PyQt5 实现交互界面：
#LoginWindow：登录界面，支持身份切换（学生/教师）。
#StudentWindow：展示学生成绩表格及排名。
#TeacherWindow：分页管理功能（学生管理、成绩录入、文件生成）。


import sys
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QLineEdit, QPushButton, QMessageBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QScrollArea, QComboBox, QDialog, QFormLayout, QDialogButtonBox,
    QSpinBox, QTabWidget, QListWidget, QListWidgetItem, QInputDialog, QStackedWidget
)
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon
from PyQt5.QtCore import Qt

# 全局样式配置
STYLE_SHEET = """
    QMainWindow {
        background-color: #ebebeb;  /*主窗口背景色*/
    }
    QLabel {
        font-size: 14px;
        color: #333333;  /*默认文字颜色*/
    }
    QLineEdit, QComboBox {
        padding: 8px;
        border: 1px solid #cccccc;  /*输入框边框颜色*/
        border-radius: 4px;
        background-color: white;  /*输入框背景色*/
    }
    QPushButton {
        padding: 10px 20px;
        background-color: #00FFFF;  /*主按钮背景色*/
        color: white;  /*按钮文字颜色*/
        border: none;
        border-radius: 4px;
    }
    QPushButton:hover {
        background-color: #00CCCC;  /*按钮悬停颜色*/
    }
    QTableWidget {
        gridline-color: #dddddd;  /*表格边框颜色*/
        selection-background-color: #d1e7dd;  /*表格选中颜色*/
        alternate-background-color: #f0f8ff;  /*交替行背景色*/
    }
    QTabWidget::pane {
        border: 1px solid #cccccc;  /*选项卡边框*/
    }
    QListWidget {
        background-color: #ffffff;  /*左侧导航栏背景*/
        border-right: 1px solid #eeeeee;  /*导航栏边框*/
    }
"""

# 加密配置 可修改加密参数
SECRET_KEY = b'YourSecretKey123'  # 16字节密钥
IV = b'InitializationVe'         # 16字节初始化向量

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

class GradeFile:
    @staticmethod
    def decrypt_data(filename):
        try:
            with open(filename, 'rb') as f:
                encrypted_data = f.read()
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            return json.loads(decrypted_data.decode())
        except Exception:
            return None


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


class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("学生成绩管理系统 - 登录")  #窗口标题
        self.setGeometry(100, 100, 400, 400)
        self.setFixedSize(400, 400)
        self.setFont(QFont("Microsoft YaHei", 20))  #字体设置
        
        # 主布局
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        # 标题可修改标题样式
        title_label = QLabel("成绩管理系统")
        title_label.setFont(QFont("Microsoft YaHei", 20, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50;")  #标题颜色
        main_layout.addWidget(title_label)
        
        # 身份选择
        self.role_combo = QComboBox()
        self.role_combo.addItems(["学生", "教师"])
        self.role_combo.setStyleSheet("padding: 8px;")
        main_layout.addWidget(QLabel("选择身份："))
        main_layout.addWidget(self.role_combo)
        
        # 输入区域
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("请输入用户名")
        main_layout.addWidget(QLabel("用户名："))
        main_layout.addWidget(self.name_input)
        
        self.pwd_input = QLineEdit()
        self.pwd_input.setPlaceholderText("请输入密码")
        self.pwd_input.setEchoMode(QLineEdit.Password)
        main_layout.addWidget(QLabel("密码："))
        main_layout.addWidget(self.pwd_input)
        
        # 登录按钮 可修改按钮文字
        login_btn = QPushButton("登 录")
        login_btn.setFont(QFont("Microsoft YaHei", 12))
        login_btn.clicked.connect(self.verify_login)
        main_layout.addWidget(login_btn)
        
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # 加载数据
        self.grade_data = GradeFile.decrypt_data('grade_1.enc') or {}
        self.teacher_users = [
            User("teacher", hashlib.sha256("teacher123".encode()).hexdigest(), "teacher")
        ]

    def verify_login(self):
        role = self.role_combo.currentText()
        username = self.name_input.text().strip()
        password = self.pwd_input.text().strip()
        
        if role == "教师":
            for user in self.teacher_users:
                if user.username == username and user.verify_password(password):
                    self.teacher_window = TeacherWindow(self.grade_data)
                    self.teacher_window.show()
                    self.close()
                    return
            QMessageBox.warning(self, "错误", "教师凭证无效！")
        
        elif role == "学生":
            for student in self.grade_data.get('students', []):
                s = Student(
                    student['name'],
                    student['password_hash'],
                    student['scores'],
                    student['rank'],
                    self.grade_data.get('grade', 1)
                )
                if s.name == username and s.verify_password(password):
                    self.student_window = StudentWindow(s)
                    self.student_window.show()
                    self.close()
                    return
            QMessageBox.warning(self, "错误", "学生凭证无效！")

class StudentWindow(QMainWindow):
    def __init__(self, student):
        super().__init__()
        self.student = student
        self.setWindowTitle(f"{student.grade}年级成绩查看 - {student.name}")  #窗口标题
        self.setGeometry(100, 100, 800, 600)
        self.setFixedSize(800, 600)
        self.setFont(QFont("Microsoft YaHei", 10))  #字体设置
        
        # 主布局
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        # 顶部信息区域
        info_widget = QWidget()
        info_layout = QHBoxLayout()
        
        # 左侧信息 可修改显示字段
        left_info = QVBoxLayout()
        left_info.addWidget(QLabel(f"姓    名：{student.name}"))
        left_info.addWidget(QLabel(f"年    级：{student.grade}年级"))
        left_info.addWidget(QLabel(f"总科目数：{len(student.scores)}"))
        left_info.setSpacing(8)
        
        # 右侧排名 可修改排名颜色
        rank_label = QLabel(f"年级排名：{student.rank}")
        rank_label.setFont(QFont("Microsoft YaHei", 16, QFont.Bold))
        rank_label.setStyleSheet("color: #e74c3c;")  # 排名颜色
        rank_layout = QVBoxLayout()
        rank_layout.addWidget(rank_label)
        rank_layout.setAlignment(Qt.AlignRight)
        
        info_layout.addLayout(left_info)
        info_layout.addLayout(rank_layout)
        info_widget.setLayout(info_layout)
        
        # 成绩表格
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(['科目名称', '成绩'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        
        # 填充数据
        subjects = sorted(self.student.scores.items(), key=lambda x: x[1], reverse=True)
        self.table.setRowCount(len(subjects))
        
        for i, (subject, score) in enumerate(subjects):
            self.table.setItem(i, 0, QTableWidgetItem(subject))
            score_item = QTableWidgetItem(str(score))
            score_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(i, 1, score_item)
        
        # 添加到主布局
        main_layout.addWidget(info_widget)
        main_layout.addWidget(self.table)
        
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

class TeacherWindow(QMainWindow):
    def __init__(self, grade_data):
        super().__init__()
        self.grade_data = grade_data
        self.setWindowTitle("教师管理端 - 成绩管理系统")  #窗口标题
        self.setGeometry(100, 100, 1000, 700)
        self.setFont(QFont("Microsoft YaHei", 10))  #字体设置
        
        # 主布局
        main_widget = QWidget()
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # 可修改导航栏样式
        self.nav_list = QListWidget()
        self.nav_list.addItems(["学生管理", "成绩录入", "文件生成"])
        self.nav_list.setCurrentRow(0)
        self.nav_list.setMaximumWidth(150)
        self.nav_list.setStyleSheet("""
            QListWidget {
                font-size: 14px;
                color: #333333;
            }
            QListWidget::item:selected {
                background-color: #d1e7dd;  /*[T] 导航栏选中项背景*/
                color: #1a733d;
            }
        """)
        self.nav_list.itemClicked.connect(self.change_page)
        
        # 右侧内容区域
        self.content_area = QStackedWidget()
        
        # 学生管理页面
        self.student_page = QWidget()
        self.setup_student_page()
        
        # 成绩录入页面
        self.score_page = QWidget()
        self.setup_score_page()
        
        # 文件生成页面
        self.file_page = QWidget()
        self.setup_file_page()
        
        self.content_area.addWidget(self.student_page)
        self.content_area.addWidget(self.score_page)
        self.content_area.addWidget(self.file_page)
        
        main_layout.addWidget(self.nav_list)
        main_layout.addWidget(self.content_area)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # 初始化数据
        self.refresh_student_list()

    def setup_student_page(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        
        # 操作按钮 可修改按钮文字
        btn_layout = QHBoxLayout()
        self.add_student_btn = QPushButton("添加学生")
        self.delete_student_btn = QPushButton("删除学生")
        self.edit_student_btn = QPushButton("编辑学生")
        btn_layout.addWidget(self.add_student_btn)
        btn_layout.addWidget(self.delete_student_btn)
        btn_layout.addWidget(self.edit_student_btn)
        
        # 学生列表
        self.student_table = QTableWidget()
        self.student_table.setColumnCount(4)
        self.student_table.setHorizontalHeaderLabels(['姓名', '年级', '排名', '操作'])
        self.student_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addLayout(btn_layout)
        layout.addWidget(self.student_table)
        self.student_page.setLayout(layout)
        
        # 信号连接
        self.add_student_btn.clicked.connect(self.add_student)
        

    def setup_score_page(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        
        # 成绩录入表单 可修改表单字段
        self.grade_selector = QComboBox()
        self.grade_selector.addItems(["七年级", "八年级", "九年级"])
        self.grade_selector.currentTextChanged.connect(self.update_subjects)
        
        self.subject_selector = QComboBox()
        self.student_selector = QComboBox()
        self.score_input = QSpinBox()
        self.score_input.setRange(0, 100)
        
        form_layout = QFormLayout()
        form_layout.addRow("选择年级：", self.grade_selector)
        form_layout.addRow("选择科目：", self.subject_selector)
        form_layout.addRow("选择学生：", self.student_selector)
        form_layout.addRow("输入成绩：", self.score_input)
        
        self.save_score_btn = QPushButton("保存成绩")
        self.save_score_btn.clicked.connect(self.save_score)
        
        layout.addLayout(form_layout)
        layout.addWidget(self.save_score_btn)
        self.score_page.setLayout(layout)
        
        # 初始化数据
        self.update_subjects()
        self.refresh_student_selector()

    def setup_file_page(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        
        self.grade_selector_file = QComboBox()
        self.grade_selector_file.addItems(["七年级", "八年级", "九年级"])
        self.filename_input = QLineEdit("grade_1.enc")
        
        form_layout = QFormLayout()
        form_layout.addRow("选择年级：", self.grade_selector_file)
        form_layout.addRow("文件名称：", self.filename_input)
        
        self.generate_btn = QPushButton("生成加密文件")
        self.generate_btn.clicked.connect(self.generate_file)
        
        layout.addLayout(form_layout)
        layout.addWidget(self.generate_btn)
        self.file_page.setLayout(layout)

    def change_page(self, item):
        text = item.text()
        if text == "学生管理":
            self.content_area.setCurrentIndex(0)
        elif text == "成绩录入":
            self.content_area.setCurrentIndex(1)
        elif text == "文件生成":
            self.content_area.setCurrentIndex(2)

    def refresh_student_list(self):
        self.student_table.setRowCount(0)
        for student in self.grade_data.get('students', []):
            row = self.student_table.rowCount()
            self.student_table.insertRow(row)
            self.student_table.setItem(row, 0, QTableWidgetItem(student['name']))
            self.student_table.setItem(row, 1, QTableWidgetItem(str(student.get('grade', 1))))
            self.student_table.setItem(row, 2, QTableWidgetItem(str(student['rank'])))
            
            # 创建操作按钮并绑定事件
            action_btn = QPushButton("查看成绩")
            action_btn.clicked.connect(lambda _, s=student: self.view_student_scores(s))
            self.student_table.setCellWidget(row, 3, action_btn)

    def view_student_scores(self, student):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"{student['name']} 成绩详情")  #对话框标题
        dialog.setLayout(QVBoxLayout())
        
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(['科目', '成绩'])
        table.setRowCount(len(student['scores']))
        
        for i, (subject, score) in enumerate(student['scores'].items()):
            table.setItem(i, 0, QTableWidgetItem(subject))
            table.setItem(i, 1, QTableWidgetItem(str(score)))
        
        dialog.layout().addWidget(table)
        dialog.exec_()

    def add_student(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("添加学生")  #对话框标题
        layout = QFormLayout()
        
        name_input = QLineEdit()
        password_input = QLineEdit()
        grade_input = QSpinBox()
        grade_input.setRange(1, 3)
        
        layout.addRow("姓名：", name_input)
        layout.addRow("初始密码：", password_input)
        layout.addRow("年级：", grade_input)
        
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        
        layout.addRow(btn_box)
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            new_student = {
                "name": name_input.text(),
                "password_hash": hashlib.sha256(password_input.text().encode()).hexdigest(),
                "scores": {},
                "rank": 0,
                "grade": grade_input.value()
            }
            self.grade_data.setdefault('students', []).append(new_student)
            self.refresh_student_list()

    def update_subjects(self):
        current_grade = self.grade_selector.currentText().replace("年级", "")
        subjects = {
            "七": ["语文", "数学", "英语","生物","地理","历史","道德与法治"],
            "八": ["语文", "数学", "英语", "物理","生物","地理","历史","道德与法治"],
            "九": ["语文", "数学", "英语", "物理", "化学","历史","道德与法治"]
        }.get(current_grade, [])
        self.subject_selector.clear()
        self.subject_selector.addItems(subjects)

    def refresh_student_selector(self):
        self.student_selector.clear()
        students = self.grade_data.get('students', [])
        self.student_selector.addItems([s['name'] for s in students])

    def save_score(self):
        student_name = self.student_selector.currentText()
        subject = self.subject_selector.currentText()
        score = self.score_input.value()
        
        for student in self.grade_data.get('students', []):
            if student['name'] == student_name:
                student['scores'][subject] = score
                break
        
        QMessageBox.information(self, "成功", "成绩保存成功！")  #提示信息
        self.refresh_student_list()

    def generate_file(self):
        filename = self.filename_input.text()
        if GradeFile.encrypt_data(self.grade_data, filename):
            QMessageBox.information(self, "成功", f"文件 {filename} 生成成功！")  #成功提示
        else:
            QMessageBox.critical(self, "错误", "文件生成失败！")  #错误提示

def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE_SHEET)
    
    login_window = LoginWindow()
    login_window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()