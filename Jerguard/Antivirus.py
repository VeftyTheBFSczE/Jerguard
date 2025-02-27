import virustotal_python
import configparser
import webbrowser
import requests
import hashlib
import os
import time
import sys
from misc.values import Values
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QMessageBox
from qt_material import apply_stylesheet
import res.res_rc
from PyQt5.QtCore import QThread, QObject, pyqtSignal


# ScannerWorker nyní počítá celkový počet souborů, vysílá procentuální postup,
# zprávy a také jména právě skenovaných souborů
class ScannerWorker(QObject):
    finished = pyqtSignal(list)           # seznam infikovaných souborů
    progressPercent = pyqtSignal(int)       # aktuální procentuální postup (0-100)
    progressMessage = pyqtSignal(str)       # textová zpráva (např. "Infected: ...")
    scannedFile = pyqtSignal(str)           # signál s aktuálně skenovaným souborem

    def __init__(self, directory):
        super().__init__()
        self.directory = directory

    def run(self):
        # Nejprve spočítáme celkový počet souborů
        total_files = 0
        for root, dirs, files in os.walk(self.directory):
            total_files += len(files)
        scanned_files = 0
        infected_files = []
        # Procházíme všechny soubory a vysíláme jejich cestu
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                self.scannedFile.emit(file_path)
                try:
                    with open(file_path, "rb") as f:
                        file_data = f.read()
                    file_hash = hashlib.md5(file_data).hexdigest()
                    found_virus = False
                    # Kontrola proti lokálním databázím hashů
                    for hash_pack in [Values.MD5_HASHES_pack1, Values.MD5_HASHES_pack2, Values.MD5_HASHES_pack3]:
                        with open(hash_pack, "r") as f:
                            for line in f:
                                if line.startswith("#"):
                                    continue
                                if file_hash in line:
                                    found_virus = True
                                    break
                        if found_virus:
                            break
                    if found_virus:
                        infected_files.append((file_path, file_hash))
                        self.progressMessage.emit(f"Infected: {file_path}")
                except Exception:
                    pass
                scanned_files += 1
                percent = int((scanned_files / total_files) * 100) if total_files > 0 else 0
                self.progressPercent.emit(percent)
        self.finished.emit(infected_files)


class Side_Functions():
    # Změna záložky
    def change_tab(self, tab, loading_msg):
        if tab == "home":
            self.Tabs.setCurrentIndex(0)
        elif tab == "settings":
            self.Tabs.setCurrentIndex(1)
        elif tab == "scan_results":
            self.Tabs.setCurrentIndex(2)
        elif tab == "loading":
            self.Tabs.setCurrentIndex(3)
            self.label_2.setText(loading_msg)

    # Zobrazení hlášení
    def log_screen(self, message, title, msg_type):
        msgBox = QMessageBox()
        msgBox.setText(message)
        msgBox.setWindowTitle(title)
        if msg_type == "error":
            msgBox.setIcon(QMessageBox.Critical)
        elif msg_type == "info":
            msgBox.setIcon(QMessageBox.Information)
        msgBox.exec_()

    # Logování zpráv do souboru
    def log(self, message, log_type):
        if log_type == "error":
            log_path = Values.error_log_path
        else:
            log_path = Values.app_log_path
        with open(log_path, "w") as log_file:
            log_file.write(message + "\n")
        return

    # Výběr souboru pro skenování
    def browse_file(self):
        Side_Functions.change_tab(self, "loading",
            "The file is being scanned \n [NOTE] Scanning with the VirusTotal API may not work/take longer than usual")
        filepath_raw, filename_raw = os.path.split(str(QtWidgets.QFileDialog.getOpenFileName(MainWindow,
                                                                                            "Select File",
                                                                                            "")))
        filepath_raw = filepath_raw.replace("('", "")
        filename = filename_raw.replace("', 'All Files (*)')", "")
        filepath = (filepath_raw + "/" + filename)
        return str(filepath), str(filename)

    # Stažení hashů z virusshare.com, pokud ještě nejsou staženy
    def get_hashes(MainWindow, self):
        try:
            Side_Functions.change_tab(self, "loading", "getting hashes from virusshare.com")
            if os.path.isfile(Values.MD5_HASHES_pack1):
                Side_Functions.change_tab(self, "home", "")
                return
            pack_1_url = "https://virusshare.com/hashfiles/VirusShare_00000.md5"
            pack_2_url = "https://virusshare.com/hashfiles/VirusShare_00001.md5"
            pack_3_url = "https://virusshare.com/hashfiles/VirusShare_00002.md5"
            pack_1 = requests.get(pack_1_url)
            pack_2 = requests.get(pack_2_url)
            pack_3 = requests.get(pack_3_url)
            with open(Values.MD5_HASHES_pack1, "w") as f:
                f.write(pack_1.text)
            with open(Values.MD5_HASHES_pack2, "w") as f:
                f.write(pack_2.text)
            with open(Values.MD5_HASHES_pack3, "w") as f:
                f.write(pack_3.text)
            Side_Functions.change_tab(self, "home", "")
        except Exception as e:
            Side_Functions.log_screen(self, "Error: " + str(e), "Error (get Hashes)", "error")
            Side_Functions.log(self, "Error: " + str(e), "error (get Hashes)")
            Side_Functions.change_tab(self, "home", "")

    # Nastavení informací o souboru v okně výsledků
    def set_file_info(self, filename, filepath, readable_hash, virus_yes_no, VT_widget, MT_widget):
        self.FileName.setText("File Name: " + filename)
        self.FilePath.setText("File Path: " + filepath)
        self.FileHash.setText("File Hash: " + readable_hash)
        if VT_widget:
            self.VirusTotalWidget.show()
        else:
            self.VirusTotalWidget.hide()
        if MT_widget:
            self.MetaDefenderWidget.show()
        else:
            self.MetaDefenderWidget.hide()
        if virus_yes_no:
            self.IsFileVirusY_N.setStyleSheet("color: #ff3a3a;")
            self.IsFileVirusY_N.setText("Virus detected!")
        else:
            self.IsFileVirusY_N.setStyleSheet("color: #7ed321;")
            self.IsFileVirusY_N.setText("No virus found")

    # Smazání souboru
    def delete(self, file_path):
        try:
            x = file_path
            os.remove(file_path)
            try:
                open(x, "rw")
                Side_Functions.log_screen(self, "Error: Error while deleting file", "Error (delete file)", "error")
                Side_Functions.log(self, "Error: Error while deleting file", "error (delete file)")
            except:
                Side_Functions.log_screen(self, "Info: File deleted successfully", "Info (delete file)", "info")
                Side_Functions.log(self, "Info: File deleted successfully", "Info (delete file)")
        except Exception as e:
            if e == False:
                Side_Functions.log_screen(self, "Error: " + str(e), "Error (delete file)", "error")
                Side_Functions.log(self, "Error: " + str(e), "error (delete file)")
            else:
                Side_Functions.log_screen(self, "Info: Looks like the file was already deleted", "Info (delete file)", "info")
                Side_Functions.log(self, "Info: Looks like the file was already deleted", "Info (delete file)")

    # Přidání témat do ComboBoxu
    def setThemesComboBox(self):
        style = Settings.Read_Settings(MainWindow, self)[0]
        path, style = os.path.split(style)
        style = style.replace(".xml", "").replace("_", "-")
        self.ThemesComboBox.addItem(style)
        for file in os.listdir(Values.theme_path):
            file = file.replace(".xml", "").replace("_", "-")
            if style == file:
                continue
            else:
                self.ThemesComboBox.addItem(file)


# Třída pro ovládání záložek (původně boční panel)
class Tabs():
    def change_tab_home(self):
        try:
            Side_Functions.change_tab(self, "home", "")
            style = Settings.Read_Settings(MainWindow, self)[0]
            style = style.replace(".xml", "").replace("_", " ")
            style_dl, color = style.split()
            self.HomeTabButton.setStyleSheet("image: url(:/res/SideBar/home.svg);")
            self.SettingsTabButton.setStyleSheet("image: url(:/res/SideBar/settings.svg);")
            self.CurrentTabSettings.setStyleSheet("background-color: #2e2e2e;")
            self.CurrentTabHome.setStyleSheet(f"background-color: {color};")
        except:
            return

    def change_tab_settings(self):
        try:
            Side_Functions.change_tab(self, "settings", "")
            style = Settings.Read_Settings(MainWindow, self)[0]
            style = style.replace(".xml", "").replace("_", " ")
            style_dl, color = style.split()
            self.SettingsTabButton.setStyleSheet("image: url(:/res/SideBar/settings.svg);")
            self.HomeTabButton.setStyleSheet("image: url(:/res/SideBar/home.svg);")
            self.CurrentTabSettings.setStyleSheet(f"background-color: {color};")
            self.CurrentTabHome.setStyleSheet("background-color: #2e2e2e;")
        except:
            return


# Třída pro aplikaci témat
class Style():
    def style_mode(self, MainWindow, theme):
        try:
            apply_stylesheet(MainWindow, theme=Values.theme_path + theme, extra=Values.extra)
            style = theme.replace(".xml", "").replace("_", " ")
            style_dl, color = style.split()
            if style_dl == "light":
                self.SideBar.setStyleSheet("background-color: #b6b6b6;")
                self.SideBar_2.setStyleSheet("background-color: #b6b6b6;")
                self.CurrentTabHome.setStyleSheet(f"background-color: {color};")
                self.CurrentTabSettings.setStyleSheet(f"background-color: {color};")
                self.HomeTitle.setStyleSheet("background-color: #b6b6b6;")
                self.SettingsTitle.setStyleSheet("background-color: #b6b6b6;")
                self.VirusResultsTitle.setStyleSheet("background-color: #b6b6b6;")
                self.LoadingPageTitle.setStyleSheet("background-color: #b6b6b6;")
            else:
                self.SideBar.setStyleSheet("background-color: #515961;")
                self.SideBar_2.setStyleSheet("background-color: #515961;")
                self.CurrentTabHome.setStyleSheet(f"background-color: {color};")
                self.CurrentTabSettings.setStyleSheet(f"background-color: {color};")
                self.HomeTitle.setStyleSheet("background-color: #515961;")
                self.SettingsTitle.setStyleSheet("background-color: #515961;")
                self.VirusResultsTitle.setStyleSheet("background-color: #515961;")
                self.LoadingPageTitle.setStyleSheet("background-color: #515961;")
        except:
            return


# Třída pro nastavení – ukládání, načítání a aplikaci uživatelských nastavení
class Settings():
    def Save_Settings(MainWindow, self):
        Side_Functions.change_tab(self, "loading", "saving settings")
        try:
            config = configparser.ConfigParser()
            config.read(Values.app_settings_path)
            VT_api_key = str(self.VirusTotalApiKey.text())
            MT_api_key = str(self.MetaDefenderApiKey.text())
            use_VT_api = str(self.UseVirusTotalApiCheckBox.isChecked())
            use_MT_api = str(self.UseMetaDefenderApiCheckBox.isChecked())
            theme = self.ThemesComboBox.currentText().replace("-", "_") + ".xml"
            config['Config-Settings']['use_VT_api'] = str(use_VT_api)
            config['Config-Settings']['VT_api_key'] = str(VT_api_key)
            config["Config-Settings"]["use_MT_api"] = str(use_MT_api)
            config["Config-Settings"]["MT_api_key"] = str(MT_api_key)
            config["Settings"]["default_theme"] = str(theme)
            with open(Values.app_settings_path, 'w') as configfile:
                config.write(configfile)
            theme = Values.theme_path + self.ThemesComboBox.currentText().replace("-", "_") + ".xml"
            apply_stylesheet(MainWindow, theme=theme, extra=Values.extra)
            Side_Functions.change_tab(self, "settings", "")
            return
        except Exception as e:
            Side_Functions.log_screen(self, "Error: " + str(e), "Error (Save Settings)", "error")
            Side_Functions.log(self, "Error: " + str(e), "error (Save Settings)")
            Side_Functions.change_tab(self, "settings", "")

    def Read_Settings(MainWindow, self):
        config = configparser.ConfigParser()
        config.read(Values.app_settings_path)
        default_theme = config.get('Settings', 'default_theme')
        use_VT_api = config.get('Config-Settings', 'use_VT_api')
        use_MT_api = config.get('Config-Settings', 'use_MT_api')
        VT_api_key = config.get('Config-Settings', 'VT_api_key')
        MT_api_key = config.get('Config-Settings', 'MT_api_key')
        return str(default_theme), str(use_VT_api), str(use_MT_api), str(VT_api_key), str(MT_api_key)

    def Apply_Settings(MainWindow, self):
        Style.style_mode(self, MainWindow, Settings.Read_Settings(MainWindow, self)[0])
        if Settings.Read_Settings(MainWindow, self)[1] == "True":
            self.UseVirusTotalApiCheckBox.setChecked(True)
        elif Settings.Read_Settings(MainWindow, self)[1] == "False":
            self.UseVirusTotalApiCheckBox.setChecked(False)
        if Settings.Read_Settings(MainWindow, self)[2] == "True":
            self.UseMetaDefenderApiCheckBox.setChecked(True)
        elif Settings.Read_Settings(MainWindow, self)[2] == "False":
            self.UseMetaDefenderApiCheckBox.setChecked(False)
        self.VirusTotalApiKey.setText(Settings.Read_Settings(MainWindow, self)[3])
        self.MetaDefenderApiKey.setText(Settings.Read_Settings(MainWindow, self)[4])
        return


# Třída pro skenování souborů
class File_Scan():
    def SCAN(MainWindow, self):
        try:
            file_path, file_name = Side_Functions.browse_file(self)
            with open(file_path, "rb") as target_file:
                bytes_content = target_file.read()
                file_hash = hashlib.md5(bytes_content).hexdigest()
            target_file.close()
            found_virus = False
            VT_widget = False
            MT_widget = False

            # Kontrola, zda soubor odpovídá známému viru (lokálně)
            with open(Values.MD5_HASHES_pack1, "r") as f:
                for line in f:
                    if line.startswith("#"):
                        continue
                    if file_hash in line:
                        found_virus = True
                        break
            f.close()
            if not found_virus:
                with open(Values.MD5_HASHES_pack2, "r") as f:
                    for line in f:
                        if line.startswith("#"):
                            continue
                        if file_hash in line:
                            found_virus = True
                            break
            if not found_virus:
                with open(Values.MD5_HASHES_pack3, "r") as f:
                    for line in f:
                        if line.startswith("#"):
                            continue
                        if file_hash in line:
                            found_virus = True
                            break
        except Exception as e:
            Side_Functions.log_screen(self, "Error: " + str(e), "Error (scan file)", "error")
            Side_Functions.log(self, "Error: " + str(e), "error")
            Side_Functions.change_tab(self, "home", "")
            return

        # Kontrola souboru pomocí vybraných API
        class API_CHECK():
            def VT_API(self, file_path, file_name):
                self.DetectionsText.setText("-")
                try:
                    if os.path.getsize(file_path) > 32000000:
                        Side_Functions.log_screen(self, "Error: File is over 32MB", "Error (VT API)", "error")
                        Side_Functions.log(self, "Error: File is over 32MB (Virus Total api)", "error")
                    VT_API_KEY = self.VirusTotalApiKey.text()
                    if VT_API_KEY == "":
                        Side_Functions.log_screen(self, "Error: API Key is empty", "Error (VT API)", "error")
                        Side_Functions.log(self, "Error: API Key is empty (Virus Total api)", "error")
                        return
                    files = {"file": (os.path.basename(file_path), open(os.path.abspath(file_path), "rb"))}
                    with virustotal_python.Virustotal(VT_API_KEY) as vtotal:
                        resp = vtotal.request("files", files=files, method="POST")
                        id = str(resp.data["id"])

                    def scan(VT_API_KEY, id):
                        url = f"https://www.virustotal.com/api/v3/analyses/{id}"
                        headers = {
                            "accept": "application/json",
                            "X-Apikey": VT_API_KEY
                        }
                        analysis = requests.get(url, headers=headers)
                        analysis_json = analysis.json()
                        status = analysis_json["data"]["attributes"]["status"]
                        return analysis_json, status

                    while scan(VT_API_KEY, id)[1] == "queued":
                        time.sleep(2)
                    analysis_json = scan(VT_API_KEY, id)[0]
                    detections = analysis_json["data"]["attributes"]["stats"]["malicious"]
                    not_detections = analysis_json["data"]["attributes"]["stats"]["undetected"]
                    if detections > not_detections:
                        self.DetectionsText.setStyleSheet("color: #ff3a3a;")
                        self.DetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                    else:
                        self.DetectionsText.setStyleSheet("color: #7ed321;")
                        self.DetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                except Exception as e:
                    Side_Functions.log_screen(self, "Error: " + str(e), "Error (VT API)", "error")
                    Side_Functions.log(self, "Error (VT API): " + str(e), "error")

            def MT_API(self, file_hash):
                self.MetaDefenderDetectionsText.setText("-")
                try:
                    MT_API_KEY = self.MetaDefenderApiKey.text()
                    if MT_API_KEY == "":
                        Side_Functions.log_screen(self, "Error: API Key is empty", "Error (MT API)", "error")
                        Side_Functions.log(self, "Error: API Key is empty (Meta Defender api)", "error")
                        return
                    header = {"apikey": MT_API_KEY}
                    analysis = requests.get("https://api.metadefender.com/v4/hash/" + file_hash, headers=header)
                    analysis_json = analysis.json()
                    detections = analysis_json["scan_results"]["total_detected_avs"]
                    not_detections = analysis_json["scan_results"]["total_avs"]
                    half_not_detections = not_detections / 2
                    if detections > half_not_detections:
                        self.MetaDefenderDetectionsText.setStyleSheet("color: #ff3a3a;")
                        self.MetaDefenderDetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                    else:
                        self.MetaDefenderDetectionsText.setStyleSheet("color: #7ed321;")
                        self.MetaDefenderDetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                except Exception as e:
                    if analysis_json["error"]["code"] == 404003:
                        self.MetaDefenderDetectionsText.setStyleSheet("color: orange")
                        self.MetaDefenderDetectionsText.setText("Hash not found.")
                        self.label_6.setText("")
                    else:
                        Side_Functions.log_screen(self, "Error: " + str(e) + " / API RESPONSE: " + str(analysis_json),
                                                  "Error (MT API)", "error")
                        Side_Functions.log(self, "Error (MT API): " + str(e) + " / API RESPONSE: " + str(analysis_json),
                                           "error")

        if self.UseVirusTotalApiCheckBox.isChecked():
            try:
                API_CHECK.VT_API(self, file_path, file_name)
                VT_widget = True
            except:
                pass
        if self.UseMetaDefenderApiCheckBox.isChecked():
            try:
                API_CHECK.MT_API(self, file_hash)
                MT_widget = True
            except:
                pass

        self.DeleteFileButton.clicked.connect(lambda: Side_Functions.delete(self, file_path))
        if self.DetectionsText.text() == "-":
            self.DetectionsText.setStyleSheet("color: #ff3a3a;")
            self.DetectionsText.setText("ERROR")
            self.label_5.setText("")
        if self.MetaDefenderDetectionsText.text() == "-":
            self.MetaDefenderDetectionsText.setStyleSheet("color: #ff3a3a;")
            self.MetaDefenderDetectionsText.setText("ERROR")
            self.label_6.setText("")
        Side_Functions.change_tab(self, "scan_results", "")
        try:
            Side_Functions.set_file_info(self, file_name, file_path, file_hash, found_virus, VT_widget, MT_widget)
        except:
            Side_Functions.change_tab(self, "home", "")
            pass


# UI – moderní rozhraní s horní navigační lištou a záložkami
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        MainWindow.setWindowIcon(QtGui.QIcon(Values.app_ico_path))
        MainWindow.setMinimumSize(QtCore.QSize(800, 600))
        MainWindow.setMaximumSize(QtCore.QSize(800, 600))
        MainWindow.setWindowTitle(f"Jerguard- [v{Values.app_version}] [dev(s): {Values.app_developers()}]")

        # Hlavní widget a layout
        self.central_widget = QtWidgets.QWidget(MainWindow)
        self.central_layout = QtWidgets.QVBoxLayout(self.central_widget)
        self.central_widget.setObjectName("central_widget")
        MainWindow.setCentralWidget(self.central_widget)

        ## Horní navigační lišta
        self.nav_bar = QtWidgets.QHBoxLayout()
        self.nav_bar.setContentsMargins(10, 10, 10, 10)
        self.nav_bar.setSpacing(20)
        self.HomeTabButton = QtWidgets.QPushButton()
        self.HomeTabButton.setIcon(QtGui.QIcon(":/res/TopBar/home.svg"))
        self.HomeTabButton.setIconSize(QtCore.QSize(24, 24))
        self.HomeTabButton.setFlat(True)
        self.HomeTabButton.setObjectName("HomeTabButton")
        self.nav_bar.addWidget(self.HomeTabButton)
        self.SettingsTabButton = QtWidgets.QPushButton()
        self.SettingsTabButton.setIcon(QtGui.QIcon(":/res/TopBar/settings.svg"))
        self.SettingsTabButton.setIconSize(QtCore.QSize(24, 24))
        self.SettingsTabButton.setFlat(True)
        self.SettingsTabButton.setObjectName("SettingsTabButton")
        self.nav_bar.addWidget(self.SettingsTabButton)
        self.nav_bar.addStretch()
        self.version_display = QtWidgets.QLabel(f"v{Values.app_version}")
        self.version_display.setObjectName("version_display")
        self.nav_bar.addWidget(self.version_display)
        self.central_layout.addLayout(self.nav_bar)

        ## Stacked widget pro jednotlivé stránky
        self.Tabs = QtWidgets.QStackedWidget()
        self.Tabs.setObjectName("Tabs")

        ### Home Tab
        self.HomeTab = QtWidgets.QWidget()
        self.HomeTab.setObjectName("HomeTab")
        home_layout = QtWidgets.QVBoxLayout(self.HomeTab)
        self.HomeTitle = QtWidgets.QLabel("Home")
        self.HomeTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.HomeTitle.setStyleSheet("font-size: 24px; font-weight: bold;")
        home_layout.addWidget(self.HomeTitle)
        button_layout = QtWidgets.QHBoxLayout()
        self.SelectFileButton = QtWidgets.QPushButton("Scan File")
        self.SelectFileButton.setIcon(QtGui.QIcon(":/res/Buttons/scan.svg"))
        self.SelectFileButton.setIconSize(QtCore.QSize(24, 24))
        button_layout.addWidget(self.SelectFileButton)
        self.ReportIssueButton = QtWidgets.QPushButton("Report Issue")
        self.ReportIssueButton.setIcon(QtGui.QIcon(":/res/Buttons/report.svg"))
        self.ReportIssueButton.setIconSize(QtCore.QSize(24, 24))
        button_layout.addWidget(self.ReportIssueButton)
        # Přidání tlačítka pro skenování celého systému
        self.ScanSystemButton = QtWidgets.QPushButton("Scan Entire System")
        self.ScanSystemButton.setIcon(QtGui.QIcon(":/res/Buttons/scan_system.svg"))
        self.ScanSystemButton.setIconSize(QtCore.QSize(24, 24))
        button_layout.addWidget(self.ScanSystemButton)
        button_layout.addStretch()
        home_layout.addLayout(button_layout)
        self.Tabs.addWidget(self.HomeTab)

        ### Settings Tab
        self.SettingsTab = QtWidgets.QWidget()
        self.SettingsTab.setObjectName("SettingsTab")
        settings_layout = QtWidgets.QVBoxLayout(self.SettingsTab)
        self.SettingsTitle = QtWidgets.QLabel("Settings")
        self.SettingsTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.SettingsTitle.setStyleSheet("font-size: 24px; font-weight: bold;")
        settings_layout.addWidget(self.SettingsTitle)
        self.VT_layout = QtWidgets.QHBoxLayout()
        self.UseVirusTotalApiCheckBox = QtWidgets.QCheckBox("Use Virus Total API")
        self.VT_layout.addWidget(self.UseVirusTotalApiCheckBox)
        self.VirusTotalApiKey = QtWidgets.QLineEdit()
        self.VirusTotalApiKey.setPlaceholderText("Enter your Virus Total API Key here")
        self.VirusTotalApiKey.setEchoMode(QtWidgets.QLineEdit.Password)
        self.VT_layout.addWidget(self.VirusTotalApiKey)
        settings_layout.addLayout(self.VT_layout)
        self.MT_layout = QtWidgets.QHBoxLayout()
        self.UseMetaDefenderApiCheckBox = QtWidgets.QCheckBox("Use Meta Defender API to check hash")
        self.MT_layout.addWidget(self.UseMetaDefenderApiCheckBox)
        self.MetaDefenderApiKey = QtWidgets.QLineEdit()
        self.MetaDefenderApiKey.setPlaceholderText("Enter your Meta Defender API Key here")
        self.MetaDefenderApiKey.setEchoMode(QtWidgets.QLineEdit.Password)
        self.MT_layout.addWidget(self.MetaDefenderApiKey)
        settings_layout.addLayout(self.MT_layout)
        theme_layout = QtWidgets.QHBoxLayout()
        self.theme_label = QtWidgets.QLabel("Theme:")
        theme_layout.addWidget(self.theme_label)
        self.ThemesComboBox = QtWidgets.QComboBox()
        theme_layout.addWidget(self.ThemesComboBox)
        theme_layout.addStretch()
        settings_layout.addLayout(theme_layout)
        self.SaveSettingsButton = QtWidgets.QPushButton("Save Settings")
        self.SaveSettingsButton.setIcon(QtGui.QIcon(":/res/Buttons/save.svg"))
        self.SaveSettingsButton.setIconSize(QtCore.QSize(24, 24))
        settings_layout.addWidget(self.SaveSettingsButton, alignment=QtCore.Qt.AlignRight)
        self.Tabs.addWidget(self.SettingsTab)

        ### Scan Results Tab
        self.VirusScanResults_hidden = QtWidgets.QWidget()
        self.VirusScanResults_hidden.setObjectName("VirusScanResults_hidden")
        scan_layout = QtWidgets.QVBoxLayout(self.VirusScanResults_hidden)
        self.VirusResultsTitle = QtWidgets.QLabel("Virus Scan Results")
        self.VirusResultsTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.VirusResultsTitle.setStyleSheet("font-size: 24px; font-weight: bold;")
        scan_layout.addWidget(self.VirusResultsTitle)
        self.FileName = QtWidgets.QLabel("File Name: ")
        self.FilePath = QtWidgets.QLabel("File Path: ")
        self.FileHash = QtWidgets.QLabel("File Hash: ")
        scan_layout.addWidget(self.FileName)
        scan_layout.addWidget(self.FilePath)
        scan_layout.addWidget(self.FileHash)
        self.virus_indicator_layout = QtWidgets.QHBoxLayout()
        self.label = QtWidgets.QLabel("Conclusion:")
        self.virus_indicator_layout.addWidget(self.label)
        self.IsFileVirusY_N = QtWidgets.QLabel("YES")
        self.IsFileVirusY_N.setStyleSheet("color: #ff3a3a; font-weight: bold;")
        self.virus_indicator_layout.addWidget(self.IsFileVirusY_N)
        self.virus_indicator_layout.addStretch()
        scan_layout.addLayout(self.virus_indicator_layout)
        self.api_results_layout = QtWidgets.QHBoxLayout()
        self.VirusTotalWidget = QtWidgets.QWidget()
        vt_layout = QtWidgets.QVBoxLayout(self.VirusTotalWidget)
        self.label_3 = QtWidgets.QLabel("Virus Total Score")
        self.label_3.setAlignment(QtCore.Qt.AlignCenter)
        self.DetectionsText = QtWidgets.QLabel("0 | 0")
        self.DetectionsText.setAlignment(QtCore.Qt.AlignCenter)
        vt_layout.addWidget(self.label_3)
        vt_layout.addWidget(self.DetectionsText)
        self.VirusTotalWidget.setLayout(vt_layout)
        self.api_results_layout.addWidget(self.VirusTotalWidget)
        self.MetaDefenderWidget = QtWidgets.QWidget()
        mt_layout = QtWidgets.QVBoxLayout(self.MetaDefenderWidget)
        self.label_4 = QtWidgets.QLabel("Meta Defender Score")
        self.label_4.setAlignment(QtCore.Qt.AlignCenter)
        self.MetaDefenderDetectionsText = QtWidgets.QLabel("0 | 0")
        self.MetaDefenderDetectionsText.setAlignment(QtCore.Qt.AlignCenter)
        mt_layout.addWidget(self.label_4)
        mt_layout.addWidget(self.MetaDefenderDetectionsText)
        self.MetaDefenderWidget.setLayout(mt_layout)
        self.api_results_layout.addWidget(self.MetaDefenderWidget)
        self.api_results_layout.addStretch()
        scan_layout.addLayout(self.api_results_layout)
        buttons_layout = QtWidgets.QHBoxLayout()
        self.ReturnToHomeTabButton = QtWidgets.QPushButton("Return")
        self.ReturnToHomeTabButton.setIcon(QtGui.QIcon(":/res/Buttons/return.svg"))
        self.ReturnToHomeTabButton.setIconSize(QtCore.QSize(24, 24))
        buttons_layout.addWidget(self.ReturnToHomeTabButton)
        self.DeleteFileButton = QtWidgets.QPushButton("Delete File")
        self.DeleteFileButton.setIcon(QtGui.QIcon(":/res/Buttons/delete.svg"))
        self.DeleteFileButton.setIconSize(QtCore.QSize(24, 24))
        buttons_layout.addWidget(self.DeleteFileButton)
        buttons_layout.addStretch()
        scan_layout.addLayout(buttons_layout)
        self.Tabs.addWidget(self.VirusScanResults_hidden)

        ### Loading Page Tab
        self.LoadingPage = QtWidgets.QWidget()
        self.LoadingPage.setObjectName("LoadingPage")
        loading_layout = QtWidgets.QVBoxLayout(self.LoadingPage)
        self.LoadingPageTitle = QtWidgets.QLabel("Loading...")
        self.LoadingPageTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.LoadingPageTitle.setStyleSheet("font-size: 24px; font-weight: bold;")
        loading_layout.addWidget(self.LoadingPageTitle)
        self.label_2 = QtWidgets.QLabel("Please wait while your file is being scanned.")
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        loading_layout.addWidget(self.label_2)
        # Deterministický progress bar a progress label
        self.progressBar = QtWidgets.QProgressBar(self.LoadingPage)
        self.progressBar.setRange(0, 100)
        self.progressBar.setValue(0)
        loading_layout.addWidget(self.progressBar)
        self.progressLabel = QtWidgets.QLabel("")
        self.progressLabel.setAlignment(QtCore.Qt.AlignCenter)
        loading_layout.addWidget(self.progressLabel)
        # Textové pole pro výpis skenovaných souborů
        self.scannedFilesTextEdit = QtWidgets.QPlainTextEdit(self.LoadingPage)
        self.scannedFilesTextEdit.setReadOnly(True)
        loading_layout.addWidget(self.scannedFilesTextEdit)
        self.Tabs.addWidget(self.LoadingPage)

        self.central_layout.addWidget(self.Tabs)

        ##########
        Tabs.change_tab_home(self)
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        ### SET LOG TEMPLATE ###
        log_template = f"""Jerguard [v{Values.app_version}] 
##############################LOGS##############################\n"""
        Side_Functions.log(self, log_template, "error")
        Side_Functions.log(self, log_template, "app")

        ### BUTTONS ###
        self.SelectFileButton.clicked.connect(lambda: File_Scan.SCAN(MainWindow, self))
        self.ReportIssueButton.clicked.connect(lambda: webbrowser.open_new(Values.github_issues_link))
        self.ReturnToHomeTabButton.clicked.connect(lambda: Side_Functions.change_tab(self, "home", ""))
        self.HomeTabButton.clicked.connect(lambda: Tabs.change_tab_home(self))
        self.SettingsTabButton.clicked.connect(lambda: Tabs.change_tab_settings(self))
        self.SaveSettingsButton.clicked.connect(lambda: Settings.Save_Settings(MainWindow, self))
        # Připojení tlačítka pro skenování celého systému pomocí QThread
        self.ScanSystemButton.clicked.connect(lambda: self.start_system_scan(MainWindow))
        Side_Functions.setThemesComboBox(self)
        QThread.currentThread()  # zajistí, že hlavní vlákno běží správně
        # Spuštění stahování hashů v samostatném vlákně
        import threading
        threading.Thread(target=Side_Functions.get_hashes, args=(MainWindow, self)).start()
        Settings.Apply_Settings(MainWindow, self)

    def start_system_scan(self, MainWindow):
        directory = QtWidgets.QFileDialog.getExistingDirectory(MainWindow, "Select Directory to Scan", "")
        if not directory:
            return
        Side_Functions.change_tab(self, "loading", "Scanning entire system. Please wait...")
        self.progressBar.setValue(0)
        self.progressLabel.setText("Starting scan...")
        self.scannedFilesTextEdit.clear()

        self.scanThread = QThread()
        self.scannerWorker = ScannerWorker(directory)
        self.scannerWorker.moveToThread(self.scanThread)
        self.scanThread.started.connect(self.scannerWorker.run)
        self.scannerWorker.finished.connect(self.on_scan_finished)
        self.scannerWorker.finished.connect(self.scanThread.quit)
        self.scannerWorker.finished.connect(self.scannerWorker.deleteLater)
        self.scanThread.finished.connect(self.scanThread.deleteLater)
        # Připojení signálů pro aktualizaci progress baru, zpráv a seznamu souborů
        self.scannerWorker.progressPercent.connect(self.update_progress_percent)
        self.scannerWorker.progressMessage.connect(self.update_progress_message)
        self.scannerWorker.scannedFile.connect(self.update_scanned_file)
        self.scanThread.start()

    def update_progress_percent(self, percent):
        self.progressBar.setValue(percent)

    def update_progress_message(self, msg):
        self.progressLabel.setText(msg)

    def update_scanned_file(self, file_path):
        # Přidá cestu k souboru do textového pole
        self.scannedFilesTextEdit.appendPlainText(file_path)

    def on_scan_finished(self, infected_files):
        result_message = f"Scanning complete.\nFound {len(infected_files)} infected files."
        if infected_files:
            result_message += "\nInfected Files:\n" + "\n".join([file[0] for file in infected_files])
        Side_Functions.log_screen(self, result_message, "Scan Results", "info")
        self.progressBar.setValue(0)
        self.progressLabel.setText("")
        Side_Functions.change_tab(self, "home", "")

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        self.HomeTabButton.setToolTip(_translate("MainWindow", "Home"))
        self.SettingsTabButton.setToolTip(_translate("MainWindow", "Settings"))
        self.SelectFileButton.setToolTip(_translate("MainWindow", "Scan a file for viruses"))
        self.ReportIssueButton.setToolTip(_translate("MainWindow", "Report an issue on GitHub"))
        self.SaveSettingsButton.setToolTip(_translate("MainWindow", "Save your settings"))
        self.VirusTotalApiKey.setPlaceholderText(_translate("MainWindow", "Enter your Virus Total API Key here"))
        self.MetaDefenderApiKey.setPlaceholderText(_translate("MainWindow", "Enter your Meta Defender API Key here"))
        self.theme_label.setText(_translate("MainWindow", "Theme:"))
        self.FileName.setText(_translate("MainWindow", "File Name: "))
        self.FilePath.setText(_translate("MainWindow", "File Path: "))
        self.FileHash.setText(_translate("MainWindow", "File Hash: "))
        self.label.setText(_translate("MainWindow", "Conclusion:"))
        self.IsFileVirusY_N.setText(_translate("MainWindow", "YES"))
        self.ReturnToHomeTabButton.setText(_translate("MainWindow", "Return"))
        self.DeleteFileButton.setText(_translate("MainWindow", "Delete File"))
        self.label_3.setText(_translate("MainWindow", "Virus Total Score"))
        self.DetectionsText.setText(_translate("MainWindow", "0 | 0"))
        self.label_4.setText(_translate("MainWindow", "Meta Defender Score"))
        self.MetaDefenderDetectionsText.setText(_translate("MainWindow", "0 | 0"))
        self.LoadingPageTitle.setText(_translate("MainWindow", "Loading..."))
        self.label_2.setText(_translate("MainWindow", "Please wait while your file is being scanned."))
        self.version_display.setText(_translate("MainWindow", f"v{Values.app_version}"))


### CONSTRUCT THE UI ###
if __name__ == "__main__":
    if hasattr(QtCore.Qt, 'AA_EnableHighDpiScaling'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
    if hasattr(QtCore.Qt, 'AA_UseHighDpiPixmaps'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)
    app = QtWidgets.QApplication(sys.argv)
    
    # Aplikujeme základní tmavý styl s červenými akcenty (vlastní QSS)
    custom_stylesheet = """
    QMainWindow {
        background-color: #1e1e1e;
    }
    QLabel {
        color: #ffffff;
        font-family: Arial, sans-serif;
    }
    QPushButton {
        background-color: #2e2e2e;
        border: 1px solid #ff3a3a;
        border-radius: 5px;
        color: #ffffff;
        padding: 5px 10px;
    }
    QPushButton:hover {
        background-color: #ff3a3a;
    }
    QLineEdit, QComboBox, QPlainTextEdit {
        background-color: #2e2e2e;
        border: 1px solid #ff3a3a;
        border-radius: 5px;
        color: #ffffff;
        padding: 3px;
    }
    QProgressBar {
        background-color: #2e2e2e;
        border: 1px solid #ff3a3a;
        border-radius: 5px;
        text-align: center;
        color: #ffffff;
    }
    QProgressBar::chunk {
        background-color: #ff3a3a;
        border-radius: 5px;
    }
    """
    app.setStyleSheet(custom_stylesheet)
    
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
