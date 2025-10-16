#pragma once
#include <QObject>
#include <QString>
#include <string>


class PacketCapture : public QObject {
    Q_OBJECT
public:
    explicit PacketCapture(QObject *parent = nullptr);
    void startCapture(const std::string &adapter, const std::string &ip, int port);

signals:
    void packetCaptured(const QString &info); // to notify GUI
};
