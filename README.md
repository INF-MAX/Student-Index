# Student-Index
这是一个已被弃用的学生成绩管理系统方案

原理
-----
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

Othes
----------------------------
如何运行？
使用conda创建虚拟环境后安装以下依赖
pip install pycryptodome pyqt5 pyinstaller

此项目已弃用
