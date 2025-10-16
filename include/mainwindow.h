#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <cstdint>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();



private slots:
    void on_Button1_clicked();

    void on_Edit1_editingFinished();

    void on_sendPacketButton_clicked();

    void on_comboBox_activated(int index);


private:
    Ui::MainWindow *ui;

    std::vector<std::string> adapterNames;
    QStringList adapterDescs;

    uint32_t calculateChecksum(std::string type);

    std::array<uint8_t, 6> stringToMac(const QString& originalMac);


public slots:
    void on_sendAck_clicked();

private slots:
    void onAdapterSelected(int index);

    void on_pushButton_clicked();

    void on_tcpChecksumButton_clicked();

    void on_checkBox_checkStateChanged(const Qt::CheckState &arg1);

    void on_blockRSTCheckBox_checkStateChanged(const Qt::CheckState &arg1);

    void on_blockRSTCheckBox_toggled(bool checked);

    void on_startCaptureButton_clicked();

    void on_autoFill_clicked();

    void displayPacketLabel(const char *text);

    void savePacketsToCSV();

    //void on_sendAck_clicked();

    //void on_autoSendAck_stateChanged(int arg1);

    void on_pushButton_2_clicked();

    void on_sendPacketButton_2_clicked();

    void on_sendPacketButtonUDP_clicked();

    void updatePacketDetail(int row);

private:
    int selectedAdapterIndex;
};
#endif // MAINWINDOW_H
