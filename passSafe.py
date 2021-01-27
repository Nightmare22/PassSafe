#!/usr/bin/python3
# -*- coding:utf8 -*-`

########################################################################################################################
""" Import Sektion """
########################################################################################################################


from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QComboBox, QLineEdit, QListView, QPushButton, QInputDialog
from PyQt5.QtWidgets import QMessageBox, QFileDialog
from PyQt5.QtCore import Qt
from PyQt5.Qt import QStandardItemModel, QStandardItem
import sys
import os
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import base64
import json
import zipfile


########################################################################################################################
"""Account Schablone"""
########################################################################################################################


class Account:
    __str_username = ""
    __str_password = ""
    __str_platform = ""
    __str_category = ""

    def __init__(self, platform, username, password, category):
        self.__str_platform = platform
        self.__str_username = username
        self.__str_password = password
        self.__str_category = category

    def get_platform(self):
        return self.__str_platform

    def set_platform(self, platform):
        self.__str_platform = platform

    def get_username(self):
        return self.__str_username

    def set_username(self, username):
        self.__str_username = username

    def get_password(self):
        return self.__str_password

    def set_password(self, password):
        self.__str_password = password

    def get_category(self):
        return self.__str_category

    def set_category(self, category):
        self.__str_category = category

    def __repr__(self):
        return self.__str_platform + "\n" + \
               self.__str_username + "\n" + \
               self.__str_password + "\n" + \
               self.__str_category

    def __str__(self):
        return self.__str_platform + "\n" + \
               self.__str_username + "\n" + \
               self.__str_password + "\n" + \
               self.__str_category


########################################################################################################################
"""AES Verschlüsselung mit Pad Funktion"""
########################################################################################################################


class Encryption:
    __pwd = ""

    def __init__(self, password):
        self.__pwd = self.__pad(password).encode()

    @staticmethod
    def __pad(s):
        return s + "\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, content):
        iv = Random.new().read(AES.block_size)
        enc = AES.new(self.__pwd, AES.MODE_CBC, iv)
        encrypted = enc.encrypt(self.__pad(content).encode("utf-8"))
        return base64.b64encode(iv + encrypted)

    def decrypt(self, content):
        data = base64.b64decode(content)
        iv = data[:16]
        content = data[16:]
        dec = AES.new(self.__pwd, AES.MODE_CBC, iv)
        return dec.decrypt(content)


########################################################################################################################
"""Benutzeroberfläche"""
########################################################################################################################


class Ui(QWidget):
    __lstAccounts = []
    __filename_pcon = "container.pcon"
    __filename_psafe = "data.psafe"
    __base_dir = "./data/"
    __master_password = ""
    __encrypted_master_password = ""

    ##################################################
    # Diese Sektion ist für Oberflächen Events       #
    ##################################################
    def __btn_new_clicked(self):
        if "" is self.le_platform.displayText() and "" is self.le_username.displayText() \
                and "" is self.le_password.displayText():
            msg = QMessageBox(QMessageBox.Warning, "Fehler", "Du musst die Felder alle befüllen!", QMessageBox.Ok)
            msg.exec()
            return
        # Daten werden aus Oberfläche gelesen
        platform = self.le_platform.displayText()
        username = self.le_username.displayText()
        password = self.le_password.displayText()
        category = self.cbb_category.currentText()
        # Daten werden in AccountListe gespeichert
        account = Account(platform, username, password, category)
        self.__lstAccounts.append(account)
        content = self.__convert_to_str()
        # Daten werden Verschlüssel mit Masterpasswort
        enc = Encryption(self.__master_password)
        content = enc.encrypt(content).decode()
        item = QStandardItem()
        item.setText(account.get_platform() + " - " + account.get_username())
        self.__model.appendRow(item)
        self.__save(content)
        self.__clear_data()

    def __btn_del_clicked(self):
        item = self.lv_account.currentIndex()
        index = item.row()
        self.__model.removeRow(item.row())
        self.__lstAccounts.remove(self.__lstAccounts[index])
        enc = Encryption(self.__master_password)
        self.__save(enc.encrypt(self.__convert_to_str()).decode())

    def __btn_edit_clicked(self):
        index = self.lv_account.currentIndex().row()
        self.__lstAccounts[index].set_platform(self.le_platform.displayText())
        self.__lstAccounts[index].set_username(self.le_username.displayText())
        self.__lstAccounts[index].set_password(self.le_password.displayText())
        self.__lstAccounts[index].set_category(self.cbb_category.currentText())
        enc = Encryption(self.__master_password)
        self.__save(enc.encrypt(self.__convert_to_str()).decode())
        self.__clear_data()
        
    def __btn_import_clicked(self):
        fd = QFileDialog()
        filename = fd.getOpenFileName(filter="Zip Dateien (*.zip)")
        zf = zipfile.ZipFile(filename[0], "r")
        try:
            zf.extractall(self.__base_dir + "..")
        except():
            msg = QMessageBox()
            msg.setWindowTitle("Fehler")
            msg.setText("Die Passworter konnten nicht eingelesen werden!")
            msg.setIcon(QMessageBox.Warning)
            msg.exec()
        finally:
            zf.close()

    def __btn_export_clicked(self):
        fd = QFileDialog()
        filename = fd.getSaveFileName(filter="Zip Dateien (*.zip)")
        zf = zipfile.ZipFile(filename[0], mode="w")
        zf.setpassword(self.__master_password.encode("utf-8"))
        try:
            zf.write(self.__base_dir + self.__filename_pcon)
            zf.write(self.__base_dir + self.__filename_psafe)
        except():
            msg = QMessageBox()
            msg.setWindowTitle("Fehler")
            msg.setText("Die Passworter konnten nicht gesichert werden!")
            msg.setIcon(QMessageBox.Warning)
            msg.exec()
        finally:
            zf.close()
        msg = QMessageBox()
        msg.setWindowTitle("Erfolg")
        msg.setText("Die Passworter wurden gesichert.")
        msg.setIcon(QMessageBox.Information)
        msg.exec()

    def on_listview_change(self, current, previos):
        index = current.row()
        self.le_platform.setText(self.__lstAccounts[index].get_platform())
        self.le_username.setText(self.__lstAccounts[index].get_username())
        self.le_password.setText(self.__lstAccounts[index].get_password())
        self.cbb_category.setCurrentText(self.__lstAccounts[index].get_category())

    def showEvent(self, ev):
        self.__startup_procedure()
        self.__load_to_list(self.__read())
        self.__load_to_gui()

    ###################################################
    # Speichert die Daten in eine Datei               #
    ###################################################
    def __save(self, content):
        os.remove(self.__base_dir + self.__filename_pcon)
        with open(self.__base_dir + self.__filename_pcon, "w") as file:
            file.write(content)
            file.flush()

    ###################################################
    # wandelt die Liste zu String um                  #
    ###################################################
    def __convert_to_str(self):
        # Daten werden in Json String gespeichert und in Variable geschrieben
        content = ""
        for i in self.__lstAccounts:
            dict_acc = {"platform": i.get_platform(), "username": i.get_username(), "password": i.get_password(),
                        "category": i.get_category()}
            content = content + json.dumps(dict_acc) + "\n"
        return content

    ###################################################
    # Liest die Daten aus der Datei                   #
    ###################################################
    def __read(self):
        # Datei wird gelesen und in Variable gespeichert
        content = ""
        with open(self.__base_dir + self.__filename_pcon, "r") as file:
            for line in file:
                content = content + line
        if content is not "":
            # Variablen inhalt wir entschlüsselt.
            dec = Encryption(self.__master_password)
            content = dec.decrypt(content).decode()
        return content

    ###################################################
    # liest Variable in Liste ein                     #
    ###################################################
    def __load_to_list(self, content):
        # Liste wird geleert
        self.__lstAccounts.clear()
        # Variable wird in liste gesplitted
        lines = content.split("\n")
        lines.remove(lines[-1])
        # Liste wird in account liste eingelesen
        for i in lines:
            dict_acc = json.loads(i)
            account = Account(dict_acc["platform"], dict_acc["username"], dict_acc["password"], dict_acc["category"])
            self.__lstAccounts.insert(0, account)

    ###################################################
    # Liest Liste in Gui ein                          #
    ###################################################
    def __load_to_gui(self):
        for account in self.__lstAccounts:
            item = QStandardItem()
            item.setText(account.get_platform()
                         + " - " + account.get_username())
            self.__model.appendRow(item)

    ###################################################
    # Säubert alle Eingaben der Benutzerschnittstelle #
    ###################################################
    def __clear_data(self):
        # Bereinige Eingabefelder
        self.le_password.setText("")
        self.le_username.setText("")
        self.le_platform.setText("")

    ###################################################
    # Profile Laden                                   #
    ###################################################

    def __profile_import(self):
        msg = QMessageBox()
        msg.setText("möchtest du ein Profil Laden?\nDann das Programm muss einmal neu gestartet werden!")
        msg.setWindowTitle("Profil? ")
        msg.setStandardButtons(QMessageBox.No | QMessageBox.Yes)
        retval = msg.exec()
        if retval == QMessageBox.Yes:
            self.__btn_import_clicked()
            self.close()
            sys.exit(0)

    ###################################################
    # Bereitet das Programm für den Start vor         #
    ###################################################
    def __startup_procedure(self):
        if not os.path.exists("./data/data.psafe"):
            self.__profile_import()
            text, ok = QInputDialog.getText(None, "Masterpasswort festlegen",
                                            "Bitte gib dein neues Passwort ein : ",
                                            QLineEdit.Password)
            pwd1 = text
            text, ok = QInputDialog.getText(None, "Masterpasswort festlegen",
                                            "Bitte gib dein neues Passwort wiederholt ein : ",
                                            QLineEdit.Password)
            pwd2 = text
            if "" is pwd1 and "" is pwd2:
                msg = QMessageBox(QMessageBox.Warning, "Fehler",
                                  "Das password ist leer, das Programm wird beendet",
                                  QMessageBox.Ok)
                msg.exec()
                self.close()
                sys.exit(1)
            elif pwd1 == pwd2:
                self.__master_password = pwd1
            else:
                msg = QMessageBox(QMessageBox.Warning, "Fehler",
                                  "Das password ist nicht Identisch, das Programm wird beendet",
                                  QMessageBox.Ok)
                msg.exec()
                self.close()
                sys.exit(1)
            os.mkdir(self.__base_dir)
            with open(self.__base_dir + self.__filename_psafe, "w") as file:
                encrypted = hashlib.sha256(self.__master_password.encode())
                file.write(str(encrypted.hexdigest()))
                file.flush()
            with open(self.__base_dir + self.__filename_pcon, "w") as file:
                file.write("")
                file.flush()
        else:
            text, ok = QInputDialog.getText(None, "Passwort eingeben", "Bitte gib dein Password ein:",
                                            QLineEdit.Password)
            self.__encrypted_master_password = hashlib.sha256(text.strip().encode()).hexdigest()
            input_encrypted_master_password = ""
            with open(self.__base_dir + self.__filename_psafe, "r") as file:
                for line in file:
                    input_encrypted_master_password = line.strip()
            if self.__encrypted_master_password == input_encrypted_master_password:
                self.__master_password = text.strip()
            else:
                msg_box = QMessageBox(QMessageBox.Warning, "Fehler",
                                      "Das eingebene Passwort ist falsch, Programm wird geschlossen",
                                      QMessageBox.Ok)
                msg_box.exec()
                self.close()
                sys.exit(1)

    #########################################################
    # Erstellt die Oberfläche mit hilfe des Konstruktors    #
    #########################################################
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Safe")
        self.setFixedSize(600, 540)
        p = self.palette()
        p.setColor(self.backgroundRole(), Qt.gray)
        self.setPalette(p)
        lbl_category = QLabel("Kategorie", self)
        lbl_category.move(5, 5)
        self.cbb_category = QComboBox(self)
        self.cbb_category.setFixedWidth(300)
        self.cbb_category.move(5, 30)
        self.cbb_category.addItem("Webseite")
        self.cbb_category.addItem("Programm")
        self.cbb_category.addItem("Service")
        self.cbb_category.addItem("Spiel")
        lbl_platform = QLabel("Plattform", self)
        lbl_platform.move(5, 60)
        self.le_platform = QLineEdit(self)
        self.le_platform.move(5, 80)
        self.le_platform.setFixedWidth(300)
        lbl_username = QLabel("Benutzername", self)
        lbl_username.move(5, 110)
        self.le_username = QLineEdit(self)
        self.le_username.move(5, 130)
        self.le_username.setFixedWidth(300)
        lbl_password = QLabel("Passwort", self)
        lbl_password.move(5, 160)
        self.le_password = QLineEdit(self)
        self.le_password.move(5, 180)
        self.le_password.setFixedWidth(300)
        lbl_account = QLabel("Benutzerkonten", self)
        lbl_account.move(5, 210)
        self.lv_account = QListView(self)
        self.lv_account.move(5, 230)
        self.lv_account.setFixedSize(300, 300)
        self.__model = QStandardItemModel()
        self.lv_account.setModel(self.__model)
        self.lv_account.selectionModel().currentChanged.connect(self.on_listview_change)
        btn_new = QPushButton("Hinzufügen", self)
        btn_new.move(320, 30)
        btn_new.setFixedSize(270, 70)
        btn_new.clicked.connect(self.__btn_new_clicked)
        btn_del = QPushButton("Entfernen", self)
        btn_del.move(320, 130)
        btn_del.setFixedSize(270, 70)
        btn_del.clicked.connect(self.__btn_del_clicked)
        btn_edit = QPushButton("Ändern", self)
        btn_edit.move(320, 230)
        btn_edit.setFixedSize(270, 70)
        btn_edit.clicked.connect(self.__btn_edit_clicked)
        btn_import = QPushButton("Importieren", self)
        btn_import.move(320, 330)
        btn_import.setFixedSize(270, 70)
        btn_import.clicked.connect(self.__btn_import_clicked)
        btn_export = QPushButton("Exportieren", self)
        btn_export.move(320, 430)
        btn_export.setFixedSize(270, 70)
        btn_export.clicked.connect(self.__btn_export_clicked)


########################################################################################################################
"""Programmstart"""
########################################################################################################################


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Ui()
    win.show()
    app.exit(app.exec())
