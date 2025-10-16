#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "test.h"
#include "SYNLocalLinux.h"
#include "sendUDPPACKET.h"
#include "functions.h"
#include <bits/stdc++.h>
#include <cstdint>
#include <QMessageBox>
#include <winsock2.h>
#include "windivert.h"
#include "packetcapture.h"
#include <QtConcurrent/QtConcurrentRun>
#include "capture.h"
#include <ctime>
#include <QTime>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>


#pragma comment(lib, "Ws2_32.lib")
using namespace std;

HANDLE divertHandle = NULL;


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // registerPacketDisplayCallback([this](const char *text) {
    //     QMetaObject::invokeMethod(this, [this, text]() {
    //         this->displayPacketLabel(text);
    //     }, Qt::QueuedConnection);
    // });
    // registerPacketDisplayCallback([this](const char *text) {
    //     QMetaObject::invokeMethod(this, [this, text]() {
    //         int row = ui->packetTable->rowCount();
    //         ui->packetTable->insertRow(row);

    //         // For simplicity, just put the full string in the first column for now
    //         ui->packetTable->setItem(row, 0, new QTableWidgetItem(QString::fromUtf8(text)));

    //         // Later you can split the string and fill multiple columns
    //         // e.g., source IP, dest IP, port, flags, etc.
    //     }, Qt::QueuedConnection);
    // });

    registerPacketDisplayCallback([this](const char* text){
        QMetaObject::invokeMethod(this, [this, text](){
            this->displayPacketLabel(text);
        }, Qt::QueuedConnection);
    });

    // ui->packetTable->setColumnCount(8);
    // QStringList headers = {"Time", "Source IP", "SRC Port", "Destination IP", "DST Port", "SEQ", "ACK", "Flags"};
    // ui->packetTable->setHorizontalHeaderLabels(headers);
    ui->packetTable->setColumnCount(8);
    QStringList headers = {
        "Time",
        "Protocol",
        "Source IP",
        "SRC Port",
        "Destination IP",
        "DST Port",
        "Info 1",
        "Info 2"
    };
    ui->packetTable->setHorizontalHeaderLabels(headers);



    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
}



    char names[10][256];
    char descs[10][512];
    int count = get_adapter(names, descs, 10);
    //int selectedAdapterIndex;

    // if (__cplusplus == 202302L) std::cout << "C++23";
    // else if (__cplusplus == 202002L) std::cout << "C++20";
    // else if (__cplusplus == 201703L) std::cout << "C++17";
    // else if (__cplusplus == 201402L) std::cout << "C++14";
    // else if (__cplusplus == 201103L) std::cout << "C++11";
    // else if (__cplusplus == 199711L) std::cout << "C++98";
    // else std::cout << "pre-standard C++." << __cplusplus;
    // std::cout << "\n";

    ui->dstMACValueLabel->setText("");
    ui->srcMACValueLabel->setText("");
    ui->ethTypeValueLabel->setText("");
    ui->ipVerValueLabel->setText("");
    ui->protocolValueLabel->setText("");
    ui->srcIPValueLabel->setText("");
    ui->dstIPValueLabel->setText("");
    ui->srcPortValueLabel->setText("");
    ui->dstPortValueLabel->setText("");
    ui->seqValueLabel->setText("");
    ui->ackValueLabel->setText("");
    ui->dataOffsetValueLabel->setText("");
    ui->tcpFlagsValueLabel->setText("");
    ui->tcpWinValueLabel->setText("");
    ui->tcpChecksumValueLabel->setText("");
    ui->tcpUrgPtrValueLabel->setText("");
    ui->srcPortValueLabel->setText("");
    ui->dstPortValueLabel->setText("");
    ui->udpLenValueLabel->setText("");
    ui->udpChecksumValueLabel->setText("");




    qDebug() << "Adapter count (from get_adapter):" << count;

    for (int i = 0; i < count; ++i) {
        // Singling out descrption from backends descs
        QString desc = QString::fromUtf8(descs[i]);
        // Singling out name from backends names (to erascharacters)
        std::string name = names[i];

        adapterDescs.append(desc);

        qDebug() << "Adapterrrrrrr count (from get_adapter):" << count;
        std::string descToErase = descs[i];



        // Erasing last characters from device description
        auto first = descToErase.begin();
        auto last = descToErase.begin() + 17;
        descToErase.erase(first, last);



        // Removing device name to be added to adapterNames
        name.erase(0, 8);
        size_t quote = name.rfind('\'');
        if (quote != std::string::npos) {
            name.erase(quote);
        }
        // Adding back slashes to the device name for the backend
        //name.insert(7, "\\");
        //name.insert(0, "\\");

        adapterNames.push_back(name);



        size_t last_quote = descToErase.rfind("'");
        if (last_quote != std::string::npos) {
            descToErase.erase(last_quote);
        }
        QString descFixed = QString::fromUtf8(descToErase);



        //printf("String Test: %s\n", descs[i]);
        ui->comboBox->addItem(descFixed);
        //printf("CPP COUNT: %d", count);
    }
    // Source port line edit
    //ui->srcPortEdit->setValidator(new QIntValidator(0, 65535, this));


    //printf("Inside Main Selected Index: %d\n", selectedAdapterIndex);

    connect(ui->comboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onAdapterSelected);

    connect(ui->blockRSTCheckBox, &QCheckBox::toggled,
            this, &MainWindow::on_blockRSTCheckBox_toggled);


}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::onAdapterSelected(int index) {
    if (index >= 0 && index < adapterNames.size()) {
        QString displayDesc = adapterDescs[index];
        //std::string backendName = adapterNames[index];

        //qDebug() << "Selected index is: " << index;
        std::cout << "Backend adapter name: " << adapterNames[index] << std::endl;
        //qDebug() << "Backend adapter name (QDebug)" << adapterNames[index];
        //printf("selected adapter name: %s\n", adapterNames[index]);
        //QString selectedAdapter = adapterNames[index];
        qDebug() << "User selected adapter: " << displayDesc;
        //this->selectedAdapterName = selectedAdapter;
    }
}


void MainWindow::on_Edit1_editingFinished()
{

}


void MainWindow::on_Button1_clicked()
{
    //send_syn_packet();
    //QString s = ui->Edit1->text();


    //qDebug() << "User input:" << s;
    //ui->label_7->setText("Running: " + s);

    //open_cmd(s.toUtf8().data());
    //qDebug() << "Calling open_cmd...";
    //open_cmd(s.toUtf8().data());
    //qDebug() << "Finished calling open_cmd.";
}




void MainWindow::on_sendPacketButton_clicked()
{
    QMessageBox warning;
    int index = ui->comboBox->currentIndex();

    struct eth_header {
        uint8_t srcMac[6];
        uint8_t dstMac[6];
        uint16_t ethType;
    };

    struct eth_header eth_header_new;

    QString macStr = ui->scrMacEdit->text();
    QString dstStr = ui->dstMacEdit->text();
    QString ethTypeString = ui->ethTypeEdit->text();
    eth_header_new.ethType = ethTypeString.toUShort(NULL, 16);

    std::cout << "Eth Type after uint8_t " << eth_header_new.ethType;



    //eeth_header_new.ethType = ui->ethTypeEdit->text();

    //uint8_t* returnedMac;
    //returnMac = stringToMac(macStr);
    /* QString macStr_new;
    for (int i = 0; i < 6; i++) {
        macStr_new += QString("0x%1").arg(eth_header_new.srcMac[i], 2, 16, QChar('0')).toUpper();
        if (i != 5) macStr_new += ", ";
    }

    qDebug() << "Mac Address" << macStr_new; */

    std::array<uint8_t, 6> srcTmp = stringToMac(macStr);
    std::array<uint8_t, 6> dstTmp = stringToMac(dstStr);

    std::copy(srcTmp.begin(), srcTmp.end(), eth_header_new.srcMac);
    std::copy(dstTmp.begin(), dstTmp.end(), eth_header_new.dstMac);

    //IP Headers
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t iPChecksum;
    std::string src_ip;
    std::string dst_ip;


    QString IpVersionIhl = ui->ipVersionHeaderEdit->text();
    QString IpTypeOfService = ui->ipTypeOfServiceEdit->text();
    QString IpTotalLength = ui->ipTotalLengthEdit->text();
    QString IpIdentification = ui->ipIdEdit->text();
    QString IpFragmentationOffset = ui->ipFragOffEdit->text();
    QString IpTimeToLive = ui->ipTimetoLiveEdit->text();
    QString IpProtocol = ui->ipProtocolEdit->text();
    QString IP_Checksum = ui->ipChecksumEdit->text();
    QString IpSrcAddress = ui->srcIpEdit->text();
    QString IpDstAddress = ui->dstIpEdit->text();

    ver_ihl = IpVersionIhl.toUShort(NULL, 16);
    std::cout << "IP Version after uint8_t " << ver_ihl;
    tos = IpTypeOfService.toUShort(NULL, 16);
    tot_len = IpTotalLength.toUShort();
    id = IpIdentification.toUShort();
    frag_off = IpFragmentationOffset.toUShort(NULL, 16);
    ttl = IpTimeToLive.toUShort();
    protocol = IpProtocol.toUShort();
    iPChecksum = IP_Checksum.toUShort();
    src_ip = IpSrcAddress.toUtf8();
    dst_ip = IpDstAddress.toUtf8();





    //TCP Headers
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t data_offset;
    uint8_t data_shift;
    // RSV?
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;

    // Retrieving TCP Headers from front end
    QString SourcePort = ui->srcPortEdit->text();
    QString DestinationPort = ui->dstPortEdit->text();
    QString sequenceNumber = ui->seqEdit->text();
    QString AckNumber = ui->ackEdit->text();
    QString DataOffset = ui->dataOffsetEdit->text();
    QString DataShift = ui->dataShiftEdit->text();
    QString Flags = ui->flagsEdit->text();
    QString Window = ui->windowsEdit->text();
    QString Checksum = ui->checksumEdit->text();
    QString UrgentPointer = ui->urgPtrEdit->text();

    // Converting from Qstring to uints
    src_port = SourcePort.toUShort();
    dst_port = DestinationPort.toUShort();
    seq = sequenceNumber.toUInt();
    ack_seq = AckNumber.toUInt(); // Always random unless it's 0
    // Need to check if its 8 bit?
    data_offset = DataOffset.toUShort();
    data_shift = DataShift.toUShort();
    flags = Flags.toUShort(NULL, 16);
    //
    window = Window.toUShort();
    checksum = Checksum.toUShort();
    urg_ptr = UrgentPointer.toUShort();




    // bool ok
    // if (!ok) {
    //     QMessageBox::warning(this, "Invalid", "Value Must be Between 0 and 65535");
    //     return;
    // }


    // Selecting adapter
    if ((index < 0) || (index > 7)) {
        printf("Valid adapter needs to be selected!\n");
        QMessageBox::warning(this, "Invalid", "Valid Adapter Needs to be Selected!");
        return;
    }
    printf("Index inside sendPacket: %d\n", index);

    std::cout << "Inside Send Packer Backend adapter name: " << adapterNames[index] << std::endl;
    qDebug() << "Inside send packet button: " << index;

    const char* selectedAdapterforBackEnd = adapterNames[index].c_str();
    //uint16_t src_port
    // Checksum is not use here, only calculated in C
    send_syn_packet(selectedAdapterforBackEnd, src_port, dst_port, seq, ack_seq, data_offset, data_shift,
                    flags, window, /* checksum */ urg_ptr, ver_ihl, tos, tot_len, id, frag_off, ttl, protocol,
                    src_ip.c_str(), dst_ip.c_str(), eth_header_new.srcMac, eth_header_new.dstMac, eth_header_new.ethType);
}

std::array<uint8_t, 6> MainWindow::stringToMac(const QString& originalMac) {
    std::array<uint8_t, 6> returnMac{};
    QStringList parts = originalMac.split(":");


    // if (parts.size() != 6) {
    //     return QMessageBox::warning(this, "Invalid MAC", "MAC address must have 6 bytes.");
    // }

    for (int i = 0; i < 6; i++) {
        QString byteStr = parts[i].trimmed();
        returnMac[i] = static_cast<uint8_t>(byteStr.toUInt(nullptr, 16));
    }
    return returnMac;

}


void MainWindow::on_comboBox_activated(int index)
{
    selectedAdapterIndex = index;
    //printf("Index clicked: %d\n", selectedAdapterIndex);

}
void showMessage(const QString message) {

}


void MainWindow::on_pushButton_clicked()
{
    QList<QLineEdit*> ipHeader = {ui->ipVersionHeaderEdit, ui->ipTypeOfServiceEdit, ui->ipTotalLengthEdit, ui->ipIdEdit,
                                  ui->ipFragOffEdit, ui->ipTimetoLiveEdit, ui->ipProtocolEdit, ui->srcIpEdit, ui->dstIpEdit};


    for (QLineEdit* headers : ipHeader) {
        if(headers->text().isEmpty()) {
            QMessageBox::warning(this, "Invalid", "All IP Headers need to be filled in!");
            return;
        }
    }
    uint16_t finalChecksum = calculateChecksum("IP");
    std::cout << "Checksum other: 0x"
              << std::hex << std::setw(4) << std::setfill('0')
              << finalChecksum
              << std::endl;


    std::ostringstream displayChecksumStream;
    displayChecksumStream << "0x"
                    << std::hex << std::setw(4) << std::setfill('0')
                    << finalChecksum;
    std::string displayChecksum = displayChecksumStream.str();

    ui->ipChecksumEdit->setText(QString::fromStdString(displayChecksum));

}

uint32_t MainWindow::calculateChecksum(std::string type) {
    struct ip_header {
        uint8_t ver_ihl_front;
        uint8_t tos_front;
        uint16_t tot_len_front;
        uint16_t id_front;
        uint16_t frag_off_front;
        uint8_t ttl_front;
        uint8_t protocol_front;
        uint16_t checksum_front;
        uint32_t src_ip_front;
        uint32_t dst_ip_front;
    };

    struct ip_header ip_header_front;

    if (type == "IP") {
        //IP Code
        std::string src_ip_string;
        std::string dst_ip_string;





        QString IpVersionIhl = ui->ipVersionHeaderEdit->text();
        QString IpTypeOfService = ui->ipTypeOfServiceEdit->text();
        QString IpTotalLength = ui->ipTotalLengthEdit->text();
        QString IpIdentification = ui->ipIdEdit->text();
        QString IpFragmentationOffset = ui->ipFragOffEdit->text();
        QString IpTimeToLive = ui->ipTimetoLiveEdit->text();
        QString IpProtocol = ui->ipProtocolEdit->text();
        QString IP_Checksum = ui->ipChecksumEdit->text();
        QString IpSrcAddress = ui->srcIpEdit->text();
        QString IpDstAddress = ui->dstIpEdit->text();

        ip_header_front.ver_ihl_front = IpVersionIhl.toUShort(NULL, 16);
        ip_header_front.tos_front = IpTypeOfService.toUShort(NULL, 16);
        ip_header_front.tot_len_front = htons(IpTotalLength.toUShort());
        ip_header_front.id_front = htons(IpIdentification.toUShort());
        ip_header_front.frag_off_front = htons(IpFragmentationOffset.toUShort(NULL, 16));
        ip_header_front.ttl_front = IpTimeToLive.toUShort();
        ip_header_front.protocol_front = IpProtocol.toUShort();
        ip_header_front.checksum_front = 0; //IP_Checksum.toUShort();

        src_ip_string = IpSrcAddress.toUtf8();
        dst_ip_string = IpDstAddress.toUtf8();

        //std::cout << "(Works) IN IP | src IP: " << src_ip_string << std::endl;
        //std::cout << "(Works) IN IP | dst IP: " << dst_ip_string;

        ip_header_front.src_ip_front = stringToIp(src_ip_string.c_str());
        ip_header_front.dst_ip_front = stringToIp(dst_ip_string.c_str());

        //std::cout << "IN IP | src IP: " << ip_header_front.src_ip_front << std::endl;
        //std::cout << "IN IP | dst IP: " << ip_header_front.dst_ip_front;



        uint16_t finalChecksum = 0;



        finalChecksum = checksum((uint16_t*)&ip_header_front, 20);
        std::cout << "Checksum inside function: 0x"
                  << std::hex << std::setw(4) << std::setfill('0')
                  << htons(finalChecksum)
                  << std::endl;
        return htons(finalChecksum);
    }

    else if (type == "TCP") {
        //TCP Code

        // Creating a TCP Header for TCP Checksums
        struct tcp_header {
            uint16_t src_port;
            uint16_t dst_port;
            uint32_t seq;
            uint32_t ack_seq;
            uint8_t data_offset_tcp;
            uint8_t flags;
            uint16_t window;
            uint16_t checksum;
            uint16_t urg_ptr;
        };

        uint8_t data_offset;
        uint8_t data_shift;

        struct tcp_header tcp;

        // Retrieving TCP Headers from front end
        QString SourcePort = ui->srcPortEdit->text();
        QString DestinationPort = ui->dstPortEdit->text();
        QString sequenceNumber = ui->seqEdit->text();
        QString AckNumber = ui->ackEdit->text();
        QString DataOffset = ui->dataOffsetEdit->text();
        QString DataShift = ui->dataShiftEdit->text();
        QString Flags = ui->flagsEdit->text();
        QString Window = ui->windowsEdit->text();
        QString Checksum = ui->checksumEdit->text();
        QString UrgentPointer = ui->urgPtrEdit->text();

        // Converting from Qstring to uints
        tcp.src_port = htons(SourcePort.toUShort());
        tcp.dst_port = htons(DestinationPort.toUShort());
        tcp.seq = htonl(sequenceNumber.toUInt());
        tcp.ack_seq = AckNumber.toUInt(); // Always random unless it's 0
        // Need to check if its 8 bit?
        data_offset = DataOffset.toUShort();
        data_shift = DataShift.toUShort();
        tcp.data_offset_tcp = (data_offset << data_shift);
        tcp.flags = Flags.toUShort(NULL, 16);
        //
        tcp.window = htons(Window.toUShort());
        tcp.checksum = Checksum.toUShort();
        tcp.urg_ptr = UrgentPointer.toUShort();

       // uint8_t packet[60];

        uint16_t tcp_checksum;

        // Creating Pseudo Header for checksums
        struct pseudo_header {
            uint32_t src_ip;
            uint32_t dst_ip;
            uint8_t zero;
            uint8_t protocol;
            uint16_t tcp_len;
        };

        std::string src_tcp_ip;
        std::string dst_tcp_ip;

        QString src_tcp_qstring;
        QString dst_tcp_qstring;



        //struct pseudo_header* tcpHeader = (struct pseuco);
        struct pseudo_header tcpHeader;

        QString tcp_protocol = ui->ipProtocolEdit->text();

        tcpHeader.zero = 0;
        tcpHeader.protocol = tcp_protocol.toUShort();
        tcpHeader.tcp_len = htons(20);


        src_tcp_qstring = ui->srcIpEdit->text();
        dst_tcp_qstring = ui->dstIpEdit->text();


        src_tcp_ip = src_tcp_qstring.toUtf8();
        dst_tcp_ip = dst_tcp_qstring.toUtf8();

        //std::cout << "After Utf8 | src IP: " << src_tcp_ip << std::endl;
        //std::cout << "After Utf8 | dst IP: " << dst_tcp_ip;

        tcpHeader.src_ip = stringToIp(src_tcp_ip.c_str());
        tcpHeader.dst_ip = stringToIp(dst_tcp_ip.c_str());

        //std::cout << "src IP: " << tcpHeader.src_ip << std::endl;
        //std::cout << "dst IP: " << tcpHeader.dst_ip;

        uint8_t pseudo_packet[sizeof(struct pseudo_header) + 20];
        memcpy(pseudo_packet, &tcpHeader, sizeof(tcpHeader));
        memcpy(pseudo_packet + sizeof(tcpHeader), &tcp, 20);
        //tcp-checksum = checksum((uint16_t*)pseudo_packet, sizeof(pseudo_packet));

        tcp_checksum = checksum((uint16_t*)pseudo_packet, sizeof(pseudo_packet));

        std::cout << "Checksum inside tcp function: 0x"
                  << std::hex << std::setw(4) << std::setfill('0')
                  << htons(tcp_checksum)
                  << std::endl;
        return htons(tcp_checksum);

    }
    return 0;
}


void MainWindow::on_tcpChecksumButton_clicked()
{
    uint16_t final_checksum = calculateChecksum("TCP");;

    std::ostringstream displayChecksumStream;
    displayChecksumStream << "0x"
                          << std::hex << std::setw(4) << std::setfill('0')
                          << final_checksum;
    std::string displayChecksum = displayChecksumStream.str();

    ui->checksumEdit->setText(QString::fromStdString(displayChecksum));

}


void MainWindow::on_checkBox_checkStateChanged(const Qt::CheckState &arg1)
{

}


void MainWindow::on_blockRSTCheckBox_checkStateChanged(const Qt::CheckState &arg1)
{

}
void MainWindow::on_blockRSTCheckBox_toggled(bool checked)
{
    if (checked) {
        QString ip = ui->srcIpEdit->text();
        QString filter = QString("outbound and tcp.Rst == 1").arg(ip);

        divertHandle = WinDivertOpen(
            filter.toStdString().c_str(),
            WINDIVERT_LAYER_NETWORK, 0, 0
            );

        if (divertHandle == INVALID_HANDLE_VALUE) {
            qDebug() << "Failed to open WinDivert:" << GetLastError();
        } else {
            qDebug() << "Now blocking outbound RST packets to" << ip;
        }
    } else {
        if (divertHandle != NULL) {
            WinDivertClose(divertHandle);
            divertHandle = NULL;
            qDebug() << "RST blocking disabled";
        }
    }
}


void MainWindow::on_startCaptureButton_clicked()
{
    /* // Step 1: Get selected adapter index
    int index = ui->comboBox->currentIndex();
    if (index < 0 || index >= adapterNames.size()) {
        QMessageBox::warning(this, "Error", "Please select a valid adapter!");
        return;
    }

    // Step 2: Get backend adapter name
    const char* backendAdapter = adapterNames[index].c_str();

    // Step 3: Prepare monitor data
    // Store QString values to ensure lifetime for the thread
    QString ipStr = ui->srcIpEdit->text();
    int port = ui->srcPortEdit->text().toInt();

    // Create a heap-allocated MonitorData so it lives for the thread
    MonitorData* md = new MonitorData;
    md->ip = ipStr.toStdString().c_str();  // pointer valid while QString exists
    md->port = port;

    // Step 4: Run capture in background using QtConcurrent
    QtConcurrent::run([backendAdapter, md, ipStr]() {
        start_capture(backendAdapter, md);

        // Free memory after capture ends
        delete md;
    });

    // Optional: update UI to show capture started
   // ui->statusLabel->setText("Packet capture started...");
    qDebug() << "    Packet Capture Started on " << ipStr << " port " << port; */

    int index = ui->comboBox->currentIndex();
    if (index < 0 || index >= adapterNames.size()) {
        QMessageBox::warning(this, "Error", "Please select a valid adapter!");
        return;
    }

    const char* backendAdapter = adapterNames[index].c_str();

    std::string ipStr = ui->srcIpEdit->text().toStdString();
    int port = ui->srcPortEdit->text().toInt();

    PacketCapture* capture = new PacketCapture(this);
    capture->startCapture(backendAdapter, ipStr, port);



    qDebug() << "Packet Capture started on " << ipStr << " port " << port;
}


void MainWindow::on_autoFill_clicked()
{
    ui->scrMacEditAck->setText(ui->scrMacEdit->text());
    ui->dstMacEditAck->setText(ui->dstMacEdit->text());
    ui->ethTypeEditAck->setText(ui->ethTypeEdit->text());


    ui->ipVersionHeaderEditAck->setText(ui->ipVersionHeaderEdit->text());
    ui->ipTypeOfServiceEditAck->setText(ui->ipTypeOfServiceEdit->text());
    ui->ipTotalLengthEditAck->setText(ui->ipTotalLengthEdit->text());
    ui->ipIdEditAck->setText(ui->ipIdEdit->text());
    ui->ipFragOffEditAck->setText(ui->ipFragOffEdit->text());
    ui->ipTimetoLiveEditAck->setText(ui->ipTimetoLiveEdit->text());
    ui->ipProtocolEditAck->setText(ui->ipProtocolEdit->text());
    ui->srcIpEditAck->setText(ui->srcIpEdit->text());
    ui->dstIpEditAck->setText(ui->dstIpEdit->text());
    ui->ipChecksumEditAck->setText(ui->ipChecksumEdit->text());

    ui->srcPortEditAck->setText(ui->srcPortEdit->text());
    ui->dstPortEditAck->setText(ui->dstPortEdit->text());
    //ui->seqEditAck->setText(ui->seqEdit->text());
    //ui->ackEditAck->setText(ui->ackEdit->text());
    ui->dataOffsetEditAck->setText(ui->dataOffsetEdit->text());
    ui->dataShiftEditAck->setText(ui->dataShiftEdit->text());
    //ui->flagsEditAck->setText(ui->flagsEdit->text());
    ui->windowsEditAck->setText(ui->windowsEdit->text());
    ui->checksumEditAck->setText(ui->checksumEdit->text());
    ui->urgPtrEditAck->setText(ui->urgPtrEdit->text());




}


void MainWindow::on_sendAck_clicked()
{
    struct eth_header {
        uint8_t srcMac[6];
        uint8_t dstMac[6];
        uint16_t ethType;
    };

    struct eth_header eth_header_ack;

    QString srcMacQ = ui->scrMacEditAck->text();
    QString dstMacQ = ui->dstMacEditAck->text();
    QString ethTypeQ = ui->ethTypeEditAck->text();

    eth_header_ack.ethType = ethTypeQ.toUShort(NULL, 16);

    std::cout << "ACK TAB ETH TYPE: " << eth_header_ack.ethType;

    std::array<uint8_t, 6> srcTmpAck = stringToMac(srcMacQ);
    std::array<uint8_t, 6> dstTmpAck = stringToMac(dstMacQ);

    std::copy(srcTmpAck.begin(), srcTmpAck.end(), eth_header_ack.srcMac);
    std::copy(dstTmpAck.begin(), dstTmpAck.end(), eth_header_ack.dstMac);


    // IP Header
    struct ip_header {
        uint8_t ver_ihlAck;
        uint8_t tosAck;
        uint16_t tot_lenAck;
        uint16_t idAck;
        uint16_t frag_offAck;
        uint8_t ttlAck;
        uint8_t protocolAck;
        uint16_t checksumAck;
        std::string src_ipAck;
        std::string dst_ipAck;
    };

    struct ip_header ip_header_ack;

    ip_header_ack.ver_ihlAck   = (ui->ipVersionHeaderEditAck->text().toUShort(NULL, 16));
    ip_header_ack.tosAck       = (ui->ipTypeOfServiceEditAck->text().toUShort(NULL, 16));
    ip_header_ack.tot_lenAck  = (ui->ipTotalLengthEditAck->text().toUShort());
    ip_header_ack.idAck       = (ui->ipIdEditAck->text().toUShort());
    ip_header_ack.frag_offAck = (ui->ipFragOffEditAck->text().toUShort(NULL, 16));
    ip_header_ack.ttlAck       = (ui->ipTimetoLiveEditAck->text().toUShort());
    ip_header_ack.protocolAck  =  (ui->ipProtocolEditAck->text().toUShort());
    ip_header_ack.checksumAck = (ui->ipChecksumEditAck->text().toUShort()); // if hex
    ip_header_ack.src_ipAck = ui->srcIpEditAck->text().toUtf8();
    ip_header_ack.dst_ipAck = ui->dstIpEditAck->text().toUtf8();

    // TCP Header.111
    struct tcp_header {
        uint16_t src_portAck;
        uint16_t dst_portAck;
        uint32_t seqAck;
        uint32_t ack_seqAck;
        uint8_t data_offsetAck;
        uint8_t data_offsetShiftAck;
        uint8_t flagsAck;
        uint16_t windowAck;
        uint16_t checksumAck;
        uint16_t urg_ptrAck;
    };

    struct tcp_header tcp_header_ack;

    tcp_header_ack.src_portAck  = ui->srcPortEditAck->text().toUShort();
    tcp_header_ack.dst_portAck  = ui->dstPortEditAck->text().toUShort();
    //tcp_header_ack.seqAck       = ui->seqEditAck->text().toUInt();
    //tcp_header_ack.ack_seqAck   = ui->ackEditAck->text().toUInt();
    tcp_header_ack.data_offsetAck = ui->dataOffsetEditAck->text().toUShort(); // 8-bit
    tcp_header_ack.data_offsetShiftAck = ui->dataShiftEditAck->text().toUShort(); // 8-bit
    tcp_header_ack.flagsAck    = ui->flagsEditAck->text().toUShort(NULL, 16);          // hex value
    tcp_header_ack.windowAck   = ui->windowsEditAck->text().toUShort();
    tcp_header_ack.checksumAck = ui->checksumEditAck->text().toUShort();
    tcp_header_ack.urg_ptrAck  = ui->urgPtrEditAck->text().toUShort();

    /// Retrieveing the SEQ and ACK for ACK
    uint32_t synSeq   = get_syn_seq();
    uint32_t synAckSeq = get_synack_seq();

    std::cout << "After retrieveing SEQ: " << synSeq;
    std::cout << "After retrieveing ACK: " << synAckSeq;

    tcp_header_ack.seqAck = synSeq + 1;
    tcp_header_ack.ack_seqAck = synAckSeq + 1;

    std::cout << "After adding 1 to  SEQ: " << tcp_header_ack.seqAck;
    std::cout << "After adding 1 to ACK: " << tcp_header_ack.ack_seqAck;

    ui->seqEditAck->setText(QString::number(tcp_header_ack.seqAck));
    ui->ackEditAck->setText(QString::number(tcp_header_ack.ack_seqAck));

    synSeq = ui->seqEditAck->text().toUInt();
    synAckSeq = ui->ackEditAck->text().toUInt();

    std::cout << "After retrieveing SEQ (end): " << synSeq;
    std::cout << "After retrieveing ACK (end): " << synAckSeq;



    int index = ui->comboBox->currentIndex();
    if ((index < 0) || (index > 7)) {
        printf("Valid adapter needs to be selected!\n");
        QMessageBox::warning(this, "Invalid", "Valid Adapter Needs to be Selected!");
        return;
    }


    const char* selectedAdapterforBackEnd = adapterNames[index].c_str();



    send_syn_packet(selectedAdapterforBackEnd, tcp_header_ack.src_portAck, tcp_header_ack.dst_portAck, tcp_header_ack.seqAck,
                    tcp_header_ack.ack_seqAck, tcp_header_ack.data_offsetAck, tcp_header_ack.data_offsetShiftAck,
                    tcp_header_ack.flagsAck, tcp_header_ack.windowAck, /* checksum */ tcp_header_ack.urg_ptrAck,
                    ip_header_ack.ver_ihlAck, ip_header_ack.tosAck, ip_header_ack.tot_lenAck, ip_header_ack.idAck,
                    ip_header_ack.frag_offAck, ip_header_ack.ttlAck, ip_header_ack.protocolAck, ip_header_ack.src_ipAck.c_str(),
                    ip_header_ack.dst_ipAck.c_str(), eth_header_ack.srcMac, eth_header_ack.dstMac, eth_header_ack.ethType);
}


void MainWindow::displayPacketLabel(const char *text) {
    if (!text) return;

    QString str = QString::fromUtf8(text);
    int row = ui->packetTable->rowCount();
    ui->packetTable->insertRow(row);

    // Determine protocol if statement
    QString protocol;
    QString info;
    QString srcIP, dstIP;
    int srcPort = 0, dstPort = 0;

    if (str.startsWith("TCP:")) {
        protocol = "TCP";
        str = str.mid(4); // remove TCP prefix
        QStringList parts = str.split(':');
        if (parts.size() < 7) return; // sanity check

        //
        srcIP = parts[0];
        srcPort = parts[1].toInt();
        dstIP = parts[2];
        dstPort = parts[3].toInt();

        quint32 seq = parts[4].toUInt();
        quint32 ack = parts[5].toUInt();
        QString flagStr = parts[6];

        // Map TCPP mapping
        if (flagStr == "0x01") flagStr = "FIN";
        else if (flagStr == "0x02") flagStr = "SYN";
        else if (flagStr == "0x04") flagStr = "RST";
        else if (flagStr == "0x08") flagStr = "PSH";
        else if (flagStr == "0x10") flagStr = "ACK";
        else if (flagStr == "0x11") flagStr = "FIN ACK";
        else if (flagStr == "0x12") flagStr = "SYN ACK";
        else if (flagStr == "0x14") flagStr = "RST ACK";
        else if (flagStr == "0x19") flagStr = "FIN PSH ACK";
        else if (flagStr == "0x20") flagStr = "URG";

        info = QString("%1 Seq=%2 Ack=%3 Flags=%4").arg(protocol).arg(seq).arg(ack).arg(flagStr);
    }
    else if (str.startsWith("UDP:") || str.startsWith("UDP Packet:")) {
        protocol = "UDP";
        // Normalize string
        str.replace("UDP Packet:", "");
        QStringList parts = str.split(QRegularExpression("[:-> ]+"));
        if (parts.size() < 5) return;

        srcIP = parts[1];   // after "UDP Packet"
        srcPort = parts[2].toInt();
        dstIP = parts[3];
        dstPort = parts[4].toInt();

        // UDP length
        int length = 0;
        for (int i = 0; i < parts.size(); ++i) {
            if (parts[i].contains("Length")) {
                length = parts[i+1].toInt();
                break;
            }
        }

        info = QString("%1 Length=%2").arg(protocol).arg(length);
    }
    else {
        // Unknown protocol, skip
        return;
    }

    // Fill table with summary info
    QTableWidgetItem *infoItem = new QTableWidgetItem(info); // visible summary
    infoItem->setData(Qt::UserRole, str);                     // store full string for detail panel
    ui->packetTable->setItem(row, 0, new QTableWidgetItem(QTime::currentTime().toString("HH:mm:ss")));
    ui->packetTable->setItem(row, 1, new QTableWidgetItem(protocol));
    ui->packetTable->setItem(row, 2, new QTableWidgetItem(srcIP));
    ui->packetTable->setItem(row, 3, new QTableWidgetItem(QString::number(srcPort)));
    ui->packetTable->setItem(row, 4, new QTableWidgetItem(dstIP));
    ui->packetTable->setItem(row, 5, new QTableWidgetItem(QString::number(dstPort)));
    ui->packetTable->setItem(row, 6, infoItem);

    // Info button
    QPushButton *infoButton = new QPushButton("Info");
    ui->packetTable->setCellWidget(row, 7, infoButton);
    connect(infoButton, &QPushButton::clicked, [=](){
        updatePacketDetail(row);
    });
}


// void MainWindow::displayPacketLabel(const char *text) {
//     if (!text) return;

//     QString str = QString::fromUtf8(text);
//     int row = ui->packetTable->rowCount();
//     ui->packetTable->insertRow(row);

//     // Determine protocol
//     QString protocol;
//     QString info;
//     QString srcIP, dstIP;
//     int srcPort = 0, dstPort = 0;

//     if (str.startsWith("TCP:")) {
//         protocol = "TCP";
//         str = str.mid(4); // remove TCP prefix
//         QStringList parts = str.split(':');
//         if (parts.size() < 7) return; // sanity check

//         srcIP = parts[0];
//         srcPort = parts[1].toInt();
//         dstIP = parts[2];
//         dstPort = parts[3].toInt();

//         quint32 seq = parts[4].toUInt();
//         quint32 ack = parts[5].toUInt();
//         QString flagStr = parts[6];

//         // Map TCP flags from hex to readable form
//         if (flagStr == "0x01") flagStr = "FIN";
//         else if (flagStr == "0x02") flagStr = "SYN";
//         else if (flagStr == "0x04") flagStr = "RST";
//         else if (flagStr == "0x08") flagStr = "PSH";
//         else if (flagStr == "0x10") flagStr = "ACK";
//         else if (flagStr == "0x11") flagStr = "FIN ACK";
//         else if (flagStr == "0x12") flagStr = "SYN ACK";
//         else if (flagStr == "0x14") flagStr = "RST ACK";
//         else if (flagStr == "0x19") flagStr = "FIN PSH ACK";
//         else if (flagStr == "0x20") flagStr = "URG";

//         info = QString("%1 Seq=%2 Ack=%3 Flags=%4").arg(protocol).arg(seq).arg(ack).arg(flagStr);
//     }
//     else if (str.startsWith("UDP:") || str.startsWith("UDP Packet:")) {
//         protocol = "UDP";
//         // Normalize string
//         str.replace("UDP Packet:", "");
//         QStringList parts = str.split(QRegularExpression("[:-> ]+"));
//         if (parts.size() < 5) return;

//         srcIP = parts[1];   // after "UDP Packet"
//         srcPort = parts[2].toInt();
//         dstIP = parts[3];
//         dstPort = parts[4].toInt();

//         // UDP length
//         int length = 0;
//         for (int i = 0; i < parts.size(); ++i) {
//             if (parts[i].contains("Length")) {
//                 length = parts[i+1].toInt();
//                 break;
//             }
//         }

//         info = QString("%1 Length=%2").arg(protocol).arg(length);
//     }
//     else {
//         // Unknown protocol, skip
//         return;
//     }

//     // Fill table
//     ui->packetTable->setItem(row, 0, new QTableWidgetItem(QTime::currentTime().toString("HH:mm:ss")));
//     ui->packetTable->setItem(row, 1, new QTableWidgetItem(protocol));
//     ui->packetTable->setItem(row, 2, new QTableWidgetItem(srcIP));
//     ui->packetTable->setItem(row, 3, new QTableWidgetItem(QString::number(srcPort)));
//     ui->packetTable->setItem(row, 4, new QTableWidgetItem(dstIP));
//     ui->packetTable->setItem(row, 5, new QTableWidgetItem(QString::number(dstPort)));
//     ui->packetTable->setItem(row, 6, new QTableWidgetItem(info));

//     QPushButton *infoButton = new QPushButton("Info");
//     ui->packetTable->setCellWidget(row, 7, infoButton);

//     connect(infoButton, &QPushButton::clicked, [=](){
//         updatePacketDetail(row);
//     });

//     // Optional: color code rows
//     // if (protocol == "TCP") {
//     //     for (int col = 0; col <= 6; ++col)
//     //         ui->packetTable->item(row, col)->setBackground(Qt::lightGray);
//     // } else if (protocol == "UDP") {
//     //     for (int col = 0; col <= 6; ++col)
//     //         ui->packetTable->item(row, col)->setBackground(Qt::lightGreen);
//     // }
// }


void MainWindow::savePacketsToCSV()
{
    QString fileName = QFileDialog::getSaveFileName(
        this,
        "Save Packets",
        "",
        "CSV Files (*.csv);;All Files (*)"
        );

    if (fileName.isEmpty())
        return;

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
        return;

    QTextStream out(&file);

    QString mySrcIp = ui->srcIpEdit->text();
    QString mySrcIpAck = ui->srcIpEditAck->text();
    //     QString mySrcIpAck = ui->srcIpEditAck->text();

    // Write headers + new "Direction" column
    QStringList headers;
    for (int col = 0; col < ui->packetTable->columnCount(); ++col) {
        if (ui->packetTable->horizontalHeaderItem(col))
            headers << ui->packetTable->horizontalHeaderItem(col)->text();
        else
            headers << QString("Col%1").arg(col);
    }
    headers << "Direction";
    out << headers.join(",") << "\n";

    // Write rows in order
    for (int row = 0; row < ui->packetTable->rowCount(); ++row) {
        QStringList rowValues;

        for (int col = 0; col < ui->packetTable->columnCount(); ++col) {
            QTableWidgetItem *item = ui->packetTable->item(row, col);
            rowValues << (item ? item->text() : ""); // always add a value (even empty string)
        }

        // Direction based on source IP
        QString direction = "Unknown";
        QTableWidgetItem *srcItem = ui->packetTable->item(row, 1); // col 1 = Source IP
        if (srcItem) {
            if (srcItem->text() == mySrcIp || srcItem->text() == mySrcIpAck)
                direction = "Outbound";
            else
                direction = "Inbound";
        }

        rowValues << direction;

        out << rowValues.join(",") << "\n";
    }

    file.close();
}



void MainWindow::on_pushButton_2_clicked()
{
    savePacketsToCSV();
}


void MainWindow::on_sendPacketButton_2_clicked()
{
    // --- ETHERNET HEADER ---
    struct eth_header {
        uint8_t srcMac[6];
        uint8_t dstMac[6];
        uint16_t ethType;
    };

    struct eth_header eth_header_UDP;

    QString srcMacQ = ui->scrMacEditUDP->text();
    QString dstMacQ = ui->dstMacEditUDP->text();
    QString ethTypeQ = ui->ethTypeEditUDP->text();

    eth_header_UDP.ethType = ethTypeQ.toUShort(NULL, 16);

    std::array<uint8_t, 6> srcTmpUDP = stringToMac(srcMacQ);
    std::array<uint8_t, 6> dstTmpUDP = stringToMac(dstMacQ);

    std::copy(srcTmpUDP.begin(), srcTmpUDP.end(), eth_header_UDP.srcMac);
    std::copy(dstTmpUDP.begin(), dstTmpUDP.end(), eth_header_UDP.dstMac);

    // --- IP HEADER ---
    struct ip_header {
        uint8_t ver_ihl;
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        std::string src_ip;
        std::string dst_ip;
    };

    struct ip_header ip_header_UDP;

    ip_header_UDP.ver_ihl   = ui->ipVersionHeaderEditUDP->text().toUShort(NULL, 16);
    ip_header_UDP.tos       = ui->ipTypeOfServiceEditUDP->text().toUShort(NULL, 16);
    ip_header_UDP.tot_len   = ui->ipTotalLengthEditUDP->text().toUShort();
    ip_header_UDP.id        = ui->ipIdEditUDP->text().toUShort();
    ip_header_UDP.frag_off  = ui->ipFragOffEditUDP->text().toUShort(NULL, 16);
    ip_header_UDP.ttl       = ui->ipTimetoLiveEditUDP->text().toUShort();
    ip_header_UDP.protocol  = ui->ipProtocolEditUDP->text().toUShort(); // 17 for UDP
    ip_header_UDP.checksum  = ui->ipChecksumEditUDP->text().toUShort();
    ip_header_UDP.src_ip    = ui->srcIpEditUDP->text().toUtf8();
    ip_header_UDP.dst_ip    = ui->dstIpEditUDP->text().toUtf8();

    // --- UDP HEADER ---
    struct udp_header {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length;
        uint16_t checksum;
    };

    struct udp_header udp_header_UDP;

    udp_header_UDP.src_port = ui->srcPortEditUDP->text().toUShort();
    udp_header_UDP.dst_port = ui->dstPortEditUDP->text().toUShort();
    udp_header_UDP.length   = ui->ipTotalLengthEditUDP->text().toUShort();
    udp_header_UDP.checksum = ui->ipChecksumEditUDP->text().toUShort();

    // --- ADAPTER SELECTION ---
    int index = ui->comboBox->currentIndex();
    if ((index < 0) || (index > 7)) {
        QMessageBox::warning(this, "Invalid", "Valid Adapter Needs to be Selected!");
        return;
    }
    const char* selectedAdapter = adapterNames[index].c_str();

    // --- SEND UDP PACKET ---
    send_UDP_packet(selectedAdapter,
                    udp_header_UDP.src_port, udp_header_UDP.dst_port,
                    udp_header_UDP.length, udp_header_UDP.checksum,
                    ip_header_UDP.ver_ihl, ip_header_UDP.tos, ip_header_UDP.tot_len,
                    ip_header_UDP.id, ip_header_UDP.frag_off, ip_header_UDP.ttl,
                    ip_header_UDP.protocol, ip_header_UDP.src_ip.c_str(), ip_header_UDP.dst_ip.c_str(),
                    eth_header_UDP.srcMac, eth_header_UDP.dstMac, eth_header_UDP.ethType);
}


void MainWindow::on_sendPacketButtonUDP_clicked()
{
    // --- ETHERNET HEADER ---
    struct eth_header {
        uint8_t srcMac[6];
        uint8_t dstMac[6];
        uint16_t ethType;
    };

    struct eth_header eth_header_UDP;

    QString srcMacQ = ui->scrMacEditUDP->text();
    QString dstMacQ = ui->dstMacEditUDP->text();
    QString ethTypeQ = ui->ethTypeEditUDP->text();

    eth_header_UDP.ethType = ethTypeQ.toUShort(NULL, 16);

    std::array<uint8_t, 6> srcTmpUDP = stringToMac(srcMacQ);
    std::array<uint8_t, 6> dstTmpUDP = stringToMac(dstMacQ);

    std::copy(srcTmpUDP.begin(), srcTmpUDP.end(), eth_header_UDP.srcMac);
    std::copy(dstTmpUDP.begin(), dstTmpUDP.end(), eth_header_UDP.dstMac);

    // --- IP HEADER ---
    struct ip_header {
        uint8_t ver_ihl;
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        std::string src_ip;
        std::string dst_ip;
    };

    struct ip_header ip_header_UDP;

    ip_header_UDP.ver_ihl   = ui->ipVersionHeaderEditUDP->text().toUShort(NULL, 16);
    ip_header_UDP.tos       = ui->ipTypeOfServiceEditUDP->text().toUShort(NULL, 16);
    ip_header_UDP.tot_len   = ui->ipTotalLengthEditip->text().toUShort();
    ip_header_UDP.id        = ui->ipIdEditUDP->text().toUShort();
    ip_header_UDP.frag_off  = ui->ipFragOffEditUDP->text().toUShort(NULL, 16);
    ip_header_UDP.ttl       = ui->ipTimetoLiveEditUDP->text().toUShort();
    ip_header_UDP.protocol  = ui->ipProtocolEditUDP->text().toUShort(); // 17 for UDP
    ip_header_UDP.checksum  = ui->ipChecksumEditUDP->text().toUShort();
    ip_header_UDP.src_ip    = ui->srcIpEditUDP->text().toUtf8();
    ip_header_UDP.dst_ip    = ui->dstIpEditUDP->text().toUtf8();

    // --- UDP HEADER ---
    struct udp_header {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length;
        uint16_t checksum;
    };

    struct udp_header udp_header_UDP;

    udp_header_UDP.src_port = ui->srcPortEditUDP->text().toUShort();
    udp_header_UDP.dst_port = ui->dstPortEditUDP->text().toUShort();
    udp_header_UDP.length   = ui->ipTotalLengthEditUDP->text().toUShort();
    udp_header_UDP.checksum = ui->ipChecksumEditUDP->text().toUShort();

    // --- ADAPTER SELECTION ---
    int index = ui->comboBox->currentIndex();
    if ((index < 0) || (index > 7)) {
        QMessageBox::warning(this, "Invalid", "Valid Adapter Needs to be Selected!");
        return;
    }
    const char* selectedAdapter = adapterNames[index].c_str();

    // --- SEND UDP PACKET ---
    send_UDP_packet(selectedAdapter,
                    udp_header_UDP.src_port, udp_header_UDP.dst_port,
                    udp_header_UDP.length, udp_header_UDP.checksum,
                    ip_header_UDP.ver_ihl, ip_header_UDP.tos, ip_header_UDP.tot_len,
                    ip_header_UDP.id, ip_header_UDP.frag_off, ip_header_UDP.ttl,
                    ip_header_UDP.protocol, ip_header_UDP.src_ip.c_str(), ip_header_UDP.dst_ip.c_str(),
                    eth_header_UDP.srcMac, eth_header_UDP.dstMac, eth_header_UDP.ethType);
}

void MainWindow::updatePacketDetail(int row) {
    ui->dstMACValueLabel->setText("");
    ui->srcMACValueLabel->setText("");
    ui->ethTypeValueLabel->setText("");
    ui->ipVerValueLabel->setText("");
    ui->protocolValueLabel->setText("");
    ui->srcIPValueLabel->setText("");
    ui->dstIPValueLabel->setText("");
    ui->srcPortValueLabel->setText("");
    ui->dstPortValueLabel->setText("");
    ui->seqValueLabel->setText("");
    ui->ackValueLabel->setText("");
    ui->dataOffsetValueLabel->setText("");
    ui->tcpFlagsValueLabel->setText("");
    ui->tcpWinValueLabel->setText("");
    ui->tcpChecksumValueLabel->setText("");
    ui->tcpUrgPtrValueLabel->setText("");
    ui->srcPortValueLabel->setText("");
    ui->dstPortValueLabel->setText("");
    ui->udpLenValueLabel->setText("");
    ui->udpChecksumValueLabel->setText("");


    if (row < 0) return;

    QTableWidgetItem *infoItem = ui->packetTable->item(row, 6);
    if (!infoItem) return;

    QString fullText = infoItem->data(Qt::UserRole).toString();
    if (fullText.isEmpty()) fullText = infoItem->text();
    if (fullText.isEmpty()) return;

    QStringList sections = fullText.split("|");

    QString ethInfo  = sections.size() > 1 ? sections[1] : "";
    QString ipInfo   = sections.size() > 2 ? sections[2] : "";
    QString tcpUdpInfo = sections.size() > 3 ? sections[3] : "";

    // -------- ETH Parsing --------
    if (!ethInfo.isEmpty()) {
        QString ethData = ethInfo.mid(4); // remove "ETH:"
        QStringList ethFields = ethData.split(",");
        for (const QString &field : ethFields) {
            QStringList kv = field.split("=");
            if (kv.size() != 2) continue;
            QString key = kv[0].trimmed();
            QString val = kv[1].trimmed();

            if (key == "dst") ui->dstMACValueLabel->setText(val);
            else if (key == "src") ui->srcMACValueLabel->setText(val);
            else if (key == "type") ui->ethTypeValueLabel->setText(val);
        }
    }

    // -------- IP Parsing --------
    if (!ipInfo.isEmpty()) {
        QString ipData = ipInfo.mid(3); // remove "IP:"
        QStringList ipFields = ipData.split(",");
        for (const QString &field : ipFields) {
            QStringList kv = field.split("=");
            if (kv.size() != 2) continue;
            QString key = kv[0].trimmed();
            QString val = kv[1].trimmed();

            if (key == "ver") ui->ipVerValueLabel->setText(val);
            else if (key == "proto") ui->protocolValueLabel->setText(val);
            else if (key == "src") ui->srcIPValueLabel->setText(val);
            else if (key == "dst") ui->dstIPValueLabel->setText(val);
        }
    }

    // -------- TCP/UDP Parsing --------
    if (!tcpUdpInfo.isEmpty()) {
        if (tcpUdpInfo.startsWith("TCP:")) {
            QString tcpData = tcpUdpInfo.mid(4);
            QStringList tcpFields = tcpData.split(",");
            for (const QString &field : tcpFields) {
                QStringList kv = field.split("=");
                if (kv.size() != 2) continue;
                QString key = kv[0].trimmed();
                QString val = kv[1].trimmed();

                if (key == "srcport") ui->srcPortValueLabel->setText(val);
                else if (key == "dstport") ui->dstPortValueLabel->setText(val);
                else if (key == "seq") ui->seqValueLabel->setText(val);
                else if (key == "ack") ui->ackValueLabel->setText(val);
                else if (key == "offset") ui->dataOffsetValueLabel->setText(val);
                else if (key == "flags") ui->tcpFlagsValueLabel->setText(val);
                else if (key == "win") ui->tcpWinValueLabel->setText(val);
                else if (key == "checksum") ui->tcpChecksumValueLabel->setText(val);
                else if (key == "urgptr") ui->tcpUrgPtrValueLabel->setText(val);
            }
        } else if (tcpUdpInfo.startsWith("UDP:")) {
            QString udpData = tcpUdpInfo.mid(4);
            QStringList udpFields = udpData.split(",");
            for (const QString &field : udpFields) {
                QStringList kv = field.split("=");
                if (kv.size() != 2) continue;
                QString key = kv[0].trimmed();
                QString val = kv[1].trimmed();

                if (key == "srcport") ui->srcPortValueLabel->setText(val);
                else if (key == "dstport") ui->dstPortValueLabel->setText(val);
                else if (key == "len") ui->udpLenValueLabel->setText(val);
                else if (key == "checksum") ui->udpChecksumValueLabel->setText(val);
            }
        }
    }
}

