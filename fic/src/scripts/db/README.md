# Device database assets

`PCI_CLASS_ru.txt` and `USB_CLASS_ru.txt` are installed runtime lookup data.

`devices.db` is the pre-versioned database retained only as an upgrade-test
fixture. It is not installed as a seed. Fresh packages create the current
schema and canonical virtual device hierarchy through
`fic-dick --maintenance migrate-db`.
