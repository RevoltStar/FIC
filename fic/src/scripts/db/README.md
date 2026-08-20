# Device database resources

`PCI_CLASS_ru.txt` and `USB_CLASS_ru.txt` are immutable runtime lookup data.
The runtime `/opt/fic/db/devices.db` is not shipped as a seed file.

On a fresh installation, `fic-dick --maintenance initialize-db` creates the
complete device database directly at schema 1. Existing non-empty databases are
accepted only when their `application_id`, `user_version`, layout, indexes,
triggers and baseline rows match the current schema exactly.
