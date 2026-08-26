#ifndef DEVICECONTROLDAEMON_H
#define DEVICECONTROLDAEMON_H

#include <map>
#include <string>

namespace fic::device_control {

int run_daemon(const std::string& socketPath);
int forward_udev_event_to_daemon(
    const std::map<std::string, std::string>& env);

int request_permanent_check();
int request_reconciliation();
int wait_for_daemon(int timeoutSeconds);

}

#endif // DEVICECONTROLDAEMON_H