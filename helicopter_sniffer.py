import sys
from PyQt5.QtWidgets import QApplication, QWidget, QMainWindow, QLabel, QPlainTextEdit, QVBoxLayout#, QtGui


class App(QMainWindow):

    def __init__(self):
        super().__init__()
        self.title = 'Helicopter Sniffer'
        self.left = 10
        self.top = 10
        self.width = 640
        self.height = 480
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
        trafficLabel.move(100,50)
        childLabel = QLabel('Child/Device', self)
        childLabel.move(425, 50)
        websitesLabel = QLabel('Websites Visited', self)
        websitesLabel.move(75, 250)
        
        # text section
#        self.b = QPlainTextEdit(self)
#        self.b.insertPlainText("You can write text here.\n")
#        self.b.move(10,10)
#        self.b.resize(400,200)


        self.show()

    def style_choice(self, text):
        self.styleChoice.setText(text)
        QtGui.QApplication.setStyle(QtGui.QStyleFactory.create(text))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
