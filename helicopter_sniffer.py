import sys
from PyQt5.QtWidgets import QApplication, QWidget, QMainWindow, QLabel, QPlainTextEdit, QVBoxLayout, QTableWidget,QTableWidgetItem#, QtGui
from PyQt5.QtCore import pyqtSlot


class App(QMainWindow):

    def __init__(self):
        super().__init__()
        self.title = 'Helicopter Sniffer'
        self.left = 10
        self.top = 10
        self.width = 1000
        self.height = 700
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        
#        # drop down menu
#        self.styleChoice = QtGui.QLabel("Windows Vista", self)
##        self.styleChoice.move(50,150)
#
#        comboBox = QtGui.QComboBox(self)
#        comboBox.addItem("motif")
#        comboBox.addItem("Windows")
#        comboBox.addItem("cde")
#        comboBox.addItem("Plastique")
#        comboBox.addItem("Cleanlooks")
#        comboBox.addItem("windowsvista")
#        comboBox.move(50, 250)
#
#        comboBox.activated[str].connect(self.style_choice)
#
#        self.styleChoice.move(50,150)
#        comboBox.activated[str].connect(self.style_choice)

        # basic menu
        mainMenu = self.menuBar()
        fileMenu = mainMenu.addMenu('File')
        editMenu = mainMenu.addMenu('Edit')
        mainMenu.setNativeMenuBar(False)

        # status bar
        self.statusBar().showMessage('Message in statusbar.')
        
        # labels
        trafficLabel = QLabel('Traffic', self)
        trafficLabel.move(190, 55)

        childLabel = QLabel('Child/Device', self)
        childLabel.move(735, 55)

        websitesLabel = QLabel('Websites Visited', self)
        websitesLabel.move(160, 375)
        
        # text section
        trafficText = QPlainTextEdit(self)
        trafficText.insertPlainText("")
        trafficText.move(25,80)
        trafficText.resize(400,250)
        trafficText.setDisabled(True)
        
        childText = QPlainTextEdit(self)
        childText.insertPlainText("")
        childText.move(575,80)
        childText.resize(400,250)
        childText.setDisabled(True)
        
        websitesText = QPlainTextEdit(self)
        websitesText.insertPlainText("")
        websitesText.move(25,400)
        websitesText.resize(400,250)
        websitesText.setDisabled(True)


        self.show()

    def style_choice(self, text):
        self.styleChoice.setText(text)
        QtGui.QApplication.setStyle(QtGui.QStyleFactory.create(text))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
