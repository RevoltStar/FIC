#include "USBInfoCollector.h"

USBInfoCollector::USBInfoCollector()
    : UDEVInfoCollector({"ID_MODEL_ID", "ID_SERIAL", "ID_VENDOR_ID", "TYPE"}) {}
