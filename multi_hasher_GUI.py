import sys
import webbrowser
import icons #name of the file with the icons, generated from the qrc file. Instructions below

"""
HOW TO USE ICONS!!

create a qrc script with the following format

<!DOCTYPE RCC><RCC version="1.0">
<qresource>
    <file alias="NAME_TO_CALL_ICON">PATH/FILE.svg</file>
</qresource>
</RCC>

where NAME_TO_CALL_ICON and PATH/FILE.svg should be replaced by what works for you

 use this shell command to generate the py file with the binary data of the icons
 pyrcc5 -o icons.py icons.qrc

 then don't forget to add the -> import "name_of_the_python_file" <- like above """

from PyQt5 import QtCore
from PyQt5.QtCore import Qt
from PyQt5.QtCore import pyqtSlot as Slot
from PyQt5.QtWidgets import QApplication, QCheckBox, QFormLayout, QLabel, QLineEdit, QTabWidget, QVBoxLayout, QWidget, QPushButton, QDialog, QTextEdit, QMessageBox
from PyQt5.QtGui import QIcon
import hashlib



class Window(QWidget):
    def __init__(self, parent=None):
        super(Window, self).__init__(parent)
        self.setWindowTitle("Multi Hasher by Shakaw")
        self.setMinimumSize(400, 200)
        self.setMaximumSize(800, 400)

        mainlayout = QVBoxLayout()

        tabs = QTabWidget()
        tabs.addTab(self.sha1UI(), "SHA1")
        tabs.addTab(self.sha256UI(), "SHA256")
        tabs.addTab(self.sha512UI(), "SHA512")
        tabs.addTab(self.md5UI(), "MD5")
        tabs.addTab(self.aboutUI(), "ABOUT")

        self.results = QTextEdit()
        self.results.setPlaceholderText('')
        self.results.setMinimumSize(370,40)
        self.results.setMaximumSize(800,40)
        self.results.setReadOnly(True)

        mainlayout.addWidget(tabs)
        mainlayout.addWidget(self.results)
        self.setLayout(mainlayout)



    def sha1UI(self):
        sha1tab = QDialog()

        outerLayout = QVBoxLayout()

        topLayout = QFormLayout()
        self.sha1_filepath = QLineEdit()
        topLayout.addRow("Enter path of file:", self.sha1_filepath)
        self.sha1_oghash = QLineEdit()
        self.sha1_oghash.setPlaceholderText("Enter hash provided")
        topLayout.addRow(self.sha1_oghash)
        self.sha1_oghash.hide()

        optionsLayout = QVBoxLayout()
        compare_checkbox = QCheckBox("Check this if you want to provide a hash to compare",self)
        compare_checkbox.stateChanged.connect(self.check_if_checked)
        optionsLayout.addWidget(compare_checkbox, alignment=QtCore.Qt.AlignBottom)

    

        hashbtn = QPushButton()
        hashbtn.setText("Hash")
        hashbtn.setIcon(QIcon(":file-hash.svg"))
        hashbtn.setShortcut('Ctrl+H')
        hashbtn.setToolTip("Start hashing the file")
        hashbtn.setFixedSize(100,25)
        hashbtn.clicked.connect(self.sha1buttonClicked)

        outerLayout.addLayout(topLayout)
        outerLayout.addLayout(optionsLayout)
        outerLayout.addWidget(hashbtn, alignment=QtCore.Qt.AlignRight | QtCore.Qt.AlignBottom)
        sha1tab.setLayout(outerLayout)
        
        return sha1tab


    def sha256UI(self):
        sha256tab = QDialog()

        outerLayout = QVBoxLayout()

        topLayout = QFormLayout()
        self.sha256_filepath = QLineEdit()
        topLayout.addRow("Enter path of file:", self.sha256_filepath)
        self.sha256_oghash = QLineEdit()
        self.sha256_oghash.setPlaceholderText("Enter hash provided")
        topLayout.addRow(self.sha256_oghash)
        self.sha256_oghash.hide()

        optionsLayout = QVBoxLayout()
        compare_checkbox = QCheckBox("Check this if you want to provide a hash to compare",self)
        compare_checkbox.stateChanged.connect(self.check_if_checked)
        optionsLayout.addWidget(compare_checkbox, alignment=QtCore.Qt.AlignBottom)

        hashbtn = QPushButton()
        hashbtn.setText("Hash")
        hashbtn.setIcon(QIcon(":file-hash.svg"))
        hashbtn.setShortcut('Ctrl+H')
        hashbtn.setToolTip("Start hashing the file")
        hashbtn.setFixedSize(100,25)

        outerLayout.addLayout(topLayout)
        outerLayout.addLayout(optionsLayout)
        outerLayout.addWidget(hashbtn, alignment=QtCore.Qt.AlignRight | QtCore.Qt.AlignBottom)
        sha256tab.setLayout(outerLayout)

        hashbtn.clicked.connect(self.sha256buttonClicked)

        return sha256tab


    def sha512UI(self):
        sha512tab = QWidget()

        outerLayout = QVBoxLayout()

        topLayout = QFormLayout()
        self.sha512_filepath = QLineEdit()
        topLayout.addRow("Enter path of file:", self.sha512_filepath)
        self.sha512_oghash = QLineEdit()
        self.sha512_oghash.setPlaceholderText("Enter hash provided")
        topLayout.addRow(self.sha512_oghash)
        self.sha512_oghash.hide()

        optionsLayout = QVBoxLayout()
        compare_checkbox = QCheckBox("Check this if you want to provide a hash to compare",self)
        compare_checkbox.stateChanged.connect(self.check_if_checked)
        optionsLayout.addWidget(compare_checkbox, alignment=QtCore.Qt.AlignBottom)

        hashbtn = QPushButton()
        hashbtn.setText("Hash")
        hashbtn.setIcon(QIcon(":file-hash.svg"))
        hashbtn.setShortcut('Ctrl+H')
        hashbtn.setToolTip("Start hashing the file")
        hashbtn.setFixedSize(100,25)

        outerLayout.addLayout(topLayout)
        outerLayout.addLayout(optionsLayout)
        outerLayout.addWidget(hashbtn, alignment=QtCore.Qt.AlignRight | QtCore.Qt.AlignBottom)
        sha512tab.setLayout(outerLayout)

        hashbtn.clicked.connect(self.sha512buttonClicked)

        return sha512tab


    def md5UI(self):
        md5tab = QWidget()

        outerLayout = QVBoxLayout()

        topLayout = QFormLayout()
        self.md5_filepath = QLineEdit()
        topLayout.addRow("Enter path of file:", self.md5_filepath)
        self.md5_oghash = QLineEdit()
        self.md5_oghash.setPlaceholderText("Enter hash provided")
        topLayout.addRow(self.md5_oghash)
        self.md5_oghash.hide()

        optionsLayout = QVBoxLayout()
        compare_checkbox = QCheckBox("Check this if you want to provide a hash to compare",self)
        compare_checkbox.stateChanged.connect(self.check_if_checked)
        optionsLayout.addWidget(compare_checkbox, alignment=QtCore.Qt.AlignBottom)

        hashbtn = QPushButton()
        hashbtn.setText("Hash")
        hashbtn.setIcon(QIcon(":file-hash.svg"))
        hashbtn.setShortcut('Ctrl+H')
        hashbtn.setToolTip("Start hashing the file")
        hashbtn.setFixedSize(100,25)

        outerLayout.addLayout(topLayout)
        outerLayout.addLayout(optionsLayout)
        outerLayout.addWidget(hashbtn, alignment=QtCore.Qt.AlignRight | QtCore.Qt.AlignBottom)
        md5tab.setLayout(outerLayout)

        hashbtn.clicked.connect(self.md5buttonClicked)

        return md5tab


    def aboutUI(self):
        abouttab = QWidget()

        abouttablayout = QVBoxLayout()

        gitbtn = QPushButton(QIcon(":file-github.svg")," My GitHub")
        gitbtn.setToolTip("Get the source code of this program and more")
        gitbtn.setFixedSize(100,25)

        abouttablayout.addWidget(gitbtn, alignment=QtCore.Qt.AlignJustify)
        abouttab.setLayout(abouttablayout)

        gitbtn.clicked.connect(self.aboutbuttonClicked) 

        return abouttab

    def check_if_checked(self, state):
        
        if state == QtCore.Qt.Checked:
            self.sha1_oghash.show()
            self.sha256_oghash.show()
            self.sha512_oghash.show()
            self.md5_oghash.show()
        else:
            self.sha1_oghash.hide()
            self.sha256_oghash.hide()
            self.sha512_oghash.hide()
            self.md5_oghash.hide()

    @Slot()
    def sha1buttonClicked(self):

        path = self.sha1_filepath.text()
        try:
            with open(path, "rb") as f:
                bytes = f.read()
                hash = hashlib.sha1(bytes).hexdigest()
                self.results.setPlainText(hash)
        except:
            return 0

    def sha256buttonClicked(self):

        path = self.sha256_filepath.text()
        try:
            with open(path,"rb") as f:
                bytes = f.read()
                hash = hashlib.sha256(bytes).hexdigest()
                self.results.setPlainText(hash)
        except:
            return 0

    def sha512buttonClicked(self):
        
        path = self.sha512_filepath.text()
        try:
            with open(path, "rb") as f:
                bytes = f.read()
                hash = hashlib.sha512(bytes).hexdigest()
                self.results.setPlainText(hash)
        except:
            return 0

    def md5buttonClicked(self):

        path = self.md5_filepath.text()
        try:
            with open(path, "rb") as f:
                bytes = f.read()
                hash = hashlib.md5(bytes).hexdigest()
                self.results.setPlainText(hash)
        except:
            return 0
    
    def aboutbuttonClicked(self):
        webbrowser.open("https://github.com/Shakkaw?tab=repositories")


    # TODO! VALIDATE THE HASH

    # def validate_hash(self):
        
    #     newhash = self.sha1buttonClicked()
    #     oghash = self.sha1_oghash.text()

    #     if self.Validate(newhash, oghash):
    #         QMessageBox.information(self, 'Info', "Hash Match")
    #     else:
    #         QMessageBox.warning(self, 'Error', "Hash Mismatch")

    # def Validate(self, newhash, oghash):

    #     RetVal = False
    #     if (newhash == oghash):
    #         RetVal = True
 
    #     return RetVal


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Window()
    win.show()
    sys.exit(app.exec_())
    