
# Replace Finder v2.0 - Screenshare Forensic Tool

Herramienta forense en PowerShell para auditorías de Screenshare (SS), detección de reemplazos de archivos (*Replaces*) y análisis profundo de memoria del proceso DPS.

Diseñada para ejecutarse directamente en memoria desde GitHub Raw:
```powershell
powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/TU_USUARIO/TU_REPO/main/ReplaceFinder.ps1)
```
o en su sintaxis abreviada:
```powershell
irm https://raw.githubusercontent.com/TU_USUARIO/TU_REPO/main/ReplaceFinder.ps1 | iex
```

---

## 🎯 Tipos de Replaces Detectados (NTFS USN Journal)

El script implementa el análisis de secuencias y firmas exactas de motivos en el **USN Journal**:

| Tipo de Replace | Firma de Cierre / Motivos Detectados | Descripción |
| :--- | :--- | :--- |
| **Explorer** | `Rename: old name` -> `Rename: new name` -> `Rename: new name \| Close` (0x80002000) o `File Delete \| Close` (0x80000200) | Reemplazo realizado arrastrando o pegando archivos mediante `explorer.exe`. |
| **Type 1** | `Data Extend \| Data Truncation` -> `Data Extend \| Data Truncation \| Close` (`0x80000006`) | Sobrescritura directa de longitud y stream. |
| **Type 2** | `Data Truncation` (`0x00000004`) -> `Data Extend \| Data Truncation` (`0x00000006`) | Truncado y extensión sin marcas de sobrescritura previa. |
| **Copy 1** | `0x804` -> `0x806` -> `0x807` -> `0x8807` -> `0x80008807` (`Overwrite \| Extend \| Trunc \| Security \| BasicInfo \| Close`) | Reemplazo con actualización de descriptores de seguridad (`Security Change`). |
| **Copy 2** | `0x4` -> `0x6` -> `0x7` -> `0x8007` -> `0x80008007` (`Overwrite \| Extend \| Trunc \| BasicInfo \| Close`) | Reemplazo estándar de archivo sin modificación de permisos de seguridad. |

---

## 🔍 Análisis Forense & DUMP de DPS (Diagnostic Policy Service)

1. **Estado del Servicio:** Comprueba si DPS está activo o si fue detenido/deshabilitado para evitar registros.
2. **Tamper / Uptime Check:** Compara el tiempo de encendido del sistema vs el tiempo de inicio de DPS para detectar si fue **reiniciado recientemente** con el fin de vaciar la memoria.
3. **Dump de Memoria con Regex `!!` y `.exe`:**
   * Dumpea y filtra las páginas de memoria de `svchost.exe` (DPS) buscando cadenas con los regex `!!` y `\.exe`.
   * Resuelve automáticamente rutas de volumen NT (`\Device\HarddiskVolumeX`) a letras de unidad estándar (`C:\...`).
   * **Lectura de Cabecera PE (TimeDateStamp):** Lee la **Fecha de Compilación real** del archivo binario ejecutable directamente del encabezado PE.
   * **Detección de Timestomping:** Compara la fecha de compilación del PE contra la fecha de creación y modificación en el sistema de archivos NTFS. Si la fecha de creación es anterior a la fecha de compilación, alerta de inmediato por manipulación temporal.
   * **Detección de Archivos Eliminados:** Si la cadena en DPS apunta a un ejecutable que ya no existe en el disco, lo marca en rojo como `ARCHIVO NO EXISTE EN DISCO (Borrado / Reemplazado)`.

