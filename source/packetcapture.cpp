#include "PacketCapture.h"
#include "capture.h"
#include <QThread>
#include <cstring>

PacketCapture::PacketCapture(QObject *parent) : QObject(parent) {}

void PacketCapture::startCapture(const std::string &adapter, const std::string &ip, int port)
{
    printf("StartCapture called: adapter=%s, ip=%s, port=%d\n", adapter.c_str(), ip.c_str(), port);
    fflush(stdout);
    QThread* thread = QThread::create([adapter, ip, port]() mutable {
        printf("Thread started!\n"); fflush(stdout);
        // Send filters to capture()
        struct MonitorData md;
        md.port = port;
        strncpy(md.ip, ip.c_str(), sizeof(md.ip)-1);
        md.ip[sizeof(md.ip)-1] = '\0';
        // Debug
        printf("Thread MonitorData: IP=%s, Port=%d\n", md.ip, md.port);
        fflush(stdout);

        start_capture(adapter.c_str(), &md);
    });

    thread->start();
    printf("Thread started signal sent\n"); fflush(stdout);
}
