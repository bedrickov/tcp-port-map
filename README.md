# Port-Sentinel

<div align="center">

![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat-square&logo=windows)
![Language](https://img.shields.io/badge/Language-Python%203-3776AB?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=flat-square)

**Низкоуровневый аудитор активных TCP-портов и соединений Windows с сопоставлением PID.**  
*Прямой вызов `iphlpapi!GetExtendedTcpTable` без создания дочерних процессов `netstat.exe`.*

</div>

---

## Архитектура

- Извлечение полной таблицы владельцев сетевых портов через C-структуры `MIB_TCPROW_OWNER_PID`.
- Побайтовое преобразование сетевого порядка байт (Big Endian network ports) без дополнительных сетевых библиотек.
- Определение реального процесса-владельца скрытых прослушивающих портов.

## Запуск и тесты

```powershell
python tests/test_sentinel.py
python scripts/port_sentinel.py
```

## Лицензия
MIT

<!-- verified: 2026-10-30 -->