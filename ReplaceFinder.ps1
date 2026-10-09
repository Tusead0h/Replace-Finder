<#
================================================================================
 REPLACE FINDER v2.0 - SCREENSHARE FORENSIC TOOL
 Disenado para ejecutarse directamente en memoria via:
 powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/.../ReplaceFinder.ps1)
 o
 irm https://raw.githubusercontent.com/.../ReplaceFinder.ps1 | iex
================================================================================
#>

# Forzar codificacion UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ==========================================
# 1. VERIFICACION DE PERMISOS DE ADMINISTRADOR
# ==========================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ==========================================
# 2. DEFINICION DEL NUCLEO C# EN MEMORIA
# ==========================================
$CSharpSource = @'
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace ReplaceFinder {
    public class PrivilegeHelper {
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TOKEN_PRIVILEGES {
            public int PrivilegeCount;
            public long Luid;
            public int Attributes;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_QUERY = 0x0008;
        public const int SE_PRIVILEGE_ENABLED = 0x00000002;

        public static bool EnableDebugPrivilege() {
            try {
                IntPtr hToken;
                if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
                    return false;

                try {
                    long luid;
                    if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
                        return false;

                    TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                    tp.PrivilegeCount = 1;
                    tp.Luid = luid;
                    tp.Attributes = SE_PRIVILEGE_ENABLED;

                    return AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                } finally {
                    CloseHandle(hToken);
                }
            } catch {
                return false;
            }
        }
    }

    public class DosDeviceHelper {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

        public static Dictionary<string, string> GetDeviceMap() {
            Dictionary<string, string> map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try {
                foreach (string drive in Environment.GetLogicalDrives()) {
                    string d = drive.TrimEnd('\\');
                    StringBuilder sb = new StringBuilder(260);
                    if (QueryDosDevice(d, sb, 260) != 0) {
                        map[sb.ToString()] = d;
                    }
                }
            } catch {}
            return map;
        }

        public static string ResolveDevicePath(string rawPath, Dictionary<string, string> map) {
            if (string.IsNullOrEmpty(rawPath)) return rawPath;
            if (map == null || map.Count == 0) map = GetDeviceMap();

            foreach (var kvp in map) {
                if (rawPath.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase)) {
                    return kvp.Value + rawPath.Substring(kvp.Key.Length);
                }
            }
            return rawPath;
        }
    }

    public class DpsDumpEntry {
        public string RawString { get; set; }
        public string ExePath { get; set; }
        public string FileName { get; set; }
        public string CompileDate { get; set; }
        public string CreationDate { get; set; }
        public string LastWriteDate { get; set; }
        public string Status { get; set; }
        public bool IsSuspicious { get; set; }
    }

    public class DpsScanner {
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint MEM_COMMIT = 0x1000;
        public const uint PAGE_GUARD = 0x100;
        public const uint PAGE_NOACCESS = 0x01;

        public static string GetPeCompileDate(string path, out DateTime? rawCompileDate) {
            rawCompileDate = null;
            try {
                if (!File.Exists(path)) return "ARCHIVO NO EXISTE EN DISCO";
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (BinaryReader br = new BinaryReader(fs)) {
                    if (fs.Length < 0x40) return "CABECERA INVALIDA";
                    if (br.ReadUInt16() != 0x5A4D) return "NO ES FORMATO MZ/PE";
                    fs.Seek(0x3C, SeekOrigin.Begin);
                    int peOffset = br.ReadInt32();
                    if (fs.Length < peOffset + 0x18) return "PE TRUNCADO";
                    fs.Seek(peOffset, SeekOrigin.Begin);
                    if (br.ReadUInt32() != 0x00004550) return "FIRMA PE INVALIDA";
                    fs.Seek(peOffset + 8, SeekOrigin.Begin);
                    uint timeStamp = br.ReadUInt32();
                    if (timeStamp == 0) return "FECHA NO REGISTRADA (0)";
                    DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                    DateTime dt = epoch.AddSeconds(timeStamp).ToLocalTime();
                    rawCompileDate = dt;
                    return dt.ToString("yyyy-MM-dd HH:mm:ss");
                }
            } catch (Exception ex) {
                return "ERROR AL LEER: " + ex.Message;
            }
        }

        public static string ExtractPath(string text, Dictionary<string, string> devMap) {
            if (string.IsNullOrEmpty(text)) return null;

            Match m = Regex.Match(text, @"([a-zA-Z]:\\[^!*?""<>|\r\n\t]+\.exe)", RegexOptions.IgnoreCase);
            if (m.Success) {
                return m.Groups[1].Value.Trim();
            }

            Match mDev = Regex.Match(text, @"(\\Device\\HarddiskVolume\d+\\[^!*?""<>|\r\n\t]+\.exe)", RegexOptions.IgnoreCase);
            if (mDev.Success) {
                return DosDeviceHelper.ResolveDevicePath(mDev.Groups[1].Value.Trim(), devMap);
            }

            return null;
        }

        public static List<DpsDumpEntry> DumpProcessRegex(int pid, string customFilter) {
            List<DpsDumpEntry> results = new List<DpsDumpEntry>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, string> devMap = DosDeviceHelper.GetDeviceMap();

            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProcess == IntPtr.Zero) return results;

            try {
                IntPtr address = IntPtr.Zero;
                MEMORY_BASIC_INFORMATION mbi;
                uint mbiSize = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
                long maxAddr = 0x7FFFFFFF0000L;

                while ((long)address < maxAddr && VirtualQueryEx(hProcess, address, out mbi, mbiSize) != 0) {
                    if (mbi.State == MEM_COMMIT &&
                        (mbi.Protect & PAGE_GUARD) == 0 &&
                        (mbi.Protect & PAGE_NOACCESS) == 0) {

                        int chunkSize = (int)Math.Min((long)mbi.RegionSize, 1024 * 1024 * 4);
                        if (chunkSize > 0) {
                            byte[] buffer = new byte[chunkSize];
                            IntPtr readBytes;
                            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, chunkSize, out readBytes)) {
                                int count = (int)readBytes;

                                Action<string> processText = (str) => {
                                    string[] tokens = str.Split(new char[] { '\0', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                                    foreach (var t in tokens) {
                                        string line = t.Trim();
                                        if (line.Length < 5 || line.Length > 400) continue;

                                        // Filtrar cadenas relevantes con !! o .exe
                                        if (line.Contains("!!") || line.IndexOf(".exe", StringComparison.OrdinalIgnoreCase) >= 0) {
                                            string cleanPath = ExtractPath(line, devMap);
                                            string dedupeKey = cleanPath != null ? cleanPath.ToLowerInvariant() : line.ToLowerInvariant();

                                            if (!seen.Contains(dedupeKey)) {
                                                seen.Add(dedupeKey);

                                                DpsDumpEntry entry = new DpsDumpEntry {
                                                    RawString = line,
                                                    ExePath = cleanPath,
                                                    FileName = cleanPath != null ? Path.GetFileName(cleanPath) : "N/A",
                                                    CompileDate = "N/A",
                                                    CreationDate = "N/A",
                                                    LastWriteDate = "N/A",
                                                    Status = "NORMAL",
                                                    IsSuspicious = false
                                                };

                                                if (!string.IsNullOrEmpty(cleanPath)) {
                                                    if (File.Exists(cleanPath)) {
                                                        DateTime? rawCompile;
                                                        entry.CompileDate = GetPeCompileDate(cleanPath, out rawCompile);
                                                        try {
                                                            FileInfo fi = new FileInfo(cleanPath);
                                                            entry.CreationDate = fi.CreationTime.ToString("yyyy-MM-dd HH:mm:ss");
                                                            entry.LastWriteDate = fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");

                                                            // Deteccion de Timestomping
                                                            if (rawCompile.HasValue) {
                                                                if (fi.CreationTime < rawCompile.Value.AddDays(-1)) {
                                                                    entry.Status = "TIMESTOMP DETECTADO (Creacion anterior a Compilacion)";
                                                                    entry.IsSuspicious = true;
                                                                }
                                                            }
                                                        } catch {}
                                                    } else {
                                                        entry.Status = "ARCHIVO NO EXISTE EN DISCO (Borrado / Reemplazado)";
                                                        entry.IsSuspicious = true;
                                                    }

                                                    // Verificar palabras clave de cheats
                                                    string lowerPath = cleanPath.ToLowerInvariant();
                                                    string[] cheatKws = new string[] { "vape", "reach", "autoclicker", "koid", "cleaner", "phantom", "sloth", "doomsday", "slinky", "drippy", "bypassed", "destruct", "hitbox" };
                                                    foreach (var kw in cheatKws) {
                                                        if (lowerPath.Contains(kw)) {
                                                            entry.Status = "CHEAT DETECTADO (" + kw + ")";
                                                            entry.IsSuspicious = true;
                                                            break;
                                                        }
                                                    }
                                                }

                                                results.Add(entry);
                                            }
                                        }
                                    }
                                };

                                string ascii = Encoding.ASCII.GetString(buffer, 0, count);
                                processText(ascii);

                                string unicode = Encoding.Unicode.GetString(buffer, 0, count);
                                processText(unicode);
                            }
                        }
                    }
                    long next = (long)mbi.BaseAddress + (long)mbi.RegionSize;
                    if (next <= (long)address) break;
                    address = new IntPtr(next);
                }
            } finally {
                CloseHandle(hProcess);
            }

            return results;
        }
    }

    public class UsnRecord {
        public ulong Usn { get; set; }
        public uint Reason { get; set; }
        public string FileId { get; set; }
        public string FileName { get; set; }
        public string DetectedType { get; set; }
        public string Details { get; set; }
        public string ReasonSequence { get; set; }
        public bool IsHighPriority { get; set; }
    }

    public class UsnAnalyzer {
        public const uint USN_REASON_DATA_OVERWRITE        = 0x00000001;
        public const uint USN_REASON_DATA_EXTEND           = 0x00000002;
        public const uint USN_REASON_DATA_TRUNCATION       = 0x00000004;
        public const uint USN_REASON_FILE_CREATE           = 0x00000100;
        public const uint USN_REASON_FILE_DELETE           = 0x00000200;
        public const uint USN_REASON_SECURITY_CHANGE       = 0x00000800;
        public const uint USN_REASON_RENAME_OLD_NAME       = 0x00001000;
        public const uint USN_REASON_RENAME_NEW_NAME       = 0x00002000;
        public const uint USN_REASON_BASIC_INFO_CHANGE     = 0x00008000;
        public const uint USN_REASON_CLOSE                 = 0x80000000;

        // Firmas exactas de cierre segun referencia
        public const uint SIG_COPY1_CLOSE = 0x80008807;
        public const uint SIG_COPY2_CLOSE = 0x80008007;
        public const uint SIG_TYPE1_CLOSE = 0x80000006;
        public const uint SIG_TYPE2_MID   = 0x00000006;
        public const uint SIG_EXPLORER_DEL_CLOSE = 0x80000200;
        public const uint SIG_EXPLORER_REN_CLOSE = 0x80002000;

        public static string ReasonToString(uint r) {
            List<string> parts = new List<string>();
            if ((r & USN_REASON_DATA_OVERWRITE) != 0) parts.Add("Data Overwrite");
            if ((r & USN_REASON_DATA_EXTEND) != 0) parts.Add("Data Extend");
            if ((r & USN_REASON_DATA_TRUNCATION) != 0) parts.Add("Data Truncation");
            if ((r & USN_REASON_FILE_CREATE) != 0) parts.Add("File Create");
            if ((r & USN_REASON_FILE_DELETE) != 0) parts.Add("File Delete");
            if ((r & USN_REASON_SECURITY_CHANGE) != 0) parts.Add("Security Change");
            if ((r & USN_REASON_RENAME_OLD_NAME) != 0) parts.Add("Rename: old name");
            if ((r & USN_REASON_RENAME_NEW_NAME) != 0) parts.Add("Rename: new name");
            if ((r & USN_REASON_BASIC_INFO_CHANGE) != 0) parts.Add("Basic Info Change");
            if ((r & USN_REASON_CLOSE) != 0) parts.Add("Close");
            if (parts.Count == 0) return "0x" + r.ToString("X");
            return string.Join(" | ", parts.ToArray());
        }

        public static bool CheckIsHighPriority(string fileName) {
            if (string.IsNullOrEmpty(fileName)) return false;
            string fn = fileName.ToLowerInvariant();
            string[] suspExts = new string[] { ".jar", ".exe", ".dll", ".class", ".bat", ".cmd", ".vbs", ".ps1", ".zip", ".rar", ".7z" };
            foreach (var ext in suspExts) {
                if (fn.EndsWith(ext)) return true;
            }
            string[] suspKeywords = new string[] { "vape", "reach", "autoclicker", "koid", "cleaner", "replace", "phantom", "sloth", "doomsday", "slinky", "drippy", "bypassed", "destruct", "hitbox", "client", "mod" };
            foreach (var kw in suspKeywords) {
                if (fn.Contains(kw)) return true;
            }
            return false;
        }

        public static List<UsnRecord> AnalyzeJournal(string driveLetter, string[] targetNamesArray, int maxLimit) {
            List<UsnRecord> results = new List<UsnRecord>();
            HashSet<string> targetNames = null;
            if (targetNamesArray != null && targetNamesArray.Length > 0) {
                targetNames = new HashSet<string>(targetNamesArray, StringComparer.OrdinalIgnoreCase);
            }

            Dictionary<string, List<uint>> fileHistory = new Dictionary<string, List<uint>>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, string> fileNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> reportedDetections = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            ProcessStartInfo psi = new ProcessStartInfo {
                FileName = "fsutil.exe",
                Arguments = "usn readjournal " + driveLetter + " csv",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            Process proc = null;
            try {
                proc = Process.Start(psi);
            } catch {
                return results;
            }

            using (StreamReader reader = proc.StandardOutput) {
                string line;
                while ((line = reader.ReadLine()) != null) {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    string[] parts = line.Split(',');
                    if (parts.Length < 11) continue;

                    ulong usn = 0;
                    ulong.TryParse(parts[0].Trim(), out usn);

                    string reasonStr = parts[1].Trim();
                    uint reason = 0;
                    if (reasonStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) {
                        try { reason = Convert.ToUInt32(reasonStr, 16); } catch {}
                    } else {
                        uint.TryParse(reasonStr, out reason);
                    }

                    string fileId = parts[3].Trim();
                    string fileName = parts[10].Trim();

                    if (targetNames != null && targetNames.Count > 0) {
                        if (!targetNames.Contains(fileName)) continue;
                    }

                    string key = string.IsNullOrEmpty(fileId) ? fileName : fileId;
                    if (!fileHistory.ContainsKey(key)) {
                        fileHistory[key] = new List<uint>();
                        fileNames[key] = fileName;
                    }
                    fileHistory[key].Add(reason);

                    string detected = null;
                    string details = null;

                    // Evaluar Firmas de Replaces segun las razones del usuario
                    if (reason == SIG_COPY1_CLOSE) {
                        detected = "Copy 1";
                        details = "Firma exacta Copy 1 (0x80008807): Overwrite | Extend | Trunc | Security | BasicInfo | Close";
                    } else if (reason == SIG_COPY2_CLOSE) {
                        detected = "Copy 2";
                        details = "Firma exacta Copy 2 (0x80008007): Overwrite | Extend | Trunc | BasicInfo | Close";
                    } else if (reason == SIG_TYPE1_CLOSE) {
                        detected = "Type 1";
                        details = "Firma exacta Type 1 (0x80000006): Data Extend | Data Truncation | Close";
                    } else if (reason == SIG_EXPLORER_REN_CLOSE || reason == SIG_EXPLORER_DEL_CLOSE) {
                        var hist = fileHistory[key];
                        bool hasOldName = hist.Contains(USN_REASON_RENAME_OLD_NAME);
                        bool hasNewName = hist.Contains(USN_REASON_RENAME_NEW_NAME);
                        if (hasOldName || hasNewName || reason == SIG_EXPLORER_DEL_CLOSE) {
                            detected = "Explorer";
                            details = "Firma Explorer (" + (reason == SIG_EXPLORER_DEL_CLOSE ? "File Delete | Close" : "Rename: new name | Close") + ")";
                        }
                    } else if (reason == SIG_TYPE2_MID) {
                        var hist = fileHistory[key];
                        if (hist.Contains(USN_REASON_DATA_TRUNCATION) && !hist.Contains(USN_REASON_DATA_OVERWRITE)) {
                            detected = "Type 2";
                            details = "Firma Type 2: Data Truncation (0x4) -> Data Extend | Data Truncation (0x6)";
                        }
                    }

                    if (detected != null) {
                        string dedupeKey = key + "_" + detected;
                        if (!reportedDetections.Contains(dedupeKey)) {
                            reportedDetections.Add(dedupeKey);

                            List<string> seqList = new List<string>();
                            foreach (var r in fileHistory[key]) {
                                seqList.Add(ReasonToString(r));
                            }
                            string seqStr = string.Join(" ==> ", seqList.ToArray());

                            UsnRecord rec = new UsnRecord {
                                Usn = usn,
                                Reason = reason,
                                FileId = fileId,
                                FileName = fileName,
                                DetectedType = detected,
                                Details = details,
                                ReasonSequence = seqStr,
                                IsHighPriority = CheckIsHighPriority(fileName)
                            };
                            results.Add(rec);

                            if (maxLimit > 0 && results.Count >= maxLimit) break;
                        }
                    }
                }
            }

            try {
                if (!proc.HasExited) proc.Kill();
                proc.Dispose();
            } catch {}

            return results;
        }
    }
}
'@

# Compilar tipos en memoria solo si no existen previamente
if (-not ([System.Management.Automation.PSTypeName]'ReplaceFinder.UsnAnalyzer').Type) {
    Add-Type -TypeDefinition $CSharpSource -ErrorAction SilentlyContinue
}

# Habilitar privilegios de depuracion (SeDebugPrivilege) si es posible
[ReplaceFinder.PrivilegeHelper]::EnableDebugPrivilege() | Out-Null

# Variable global para guardar historial del ultimo escaneo
$global:UltimoReporte = @{
    Fecha = (Get-Date)
    TipoEscaneo = "Ninguno"
    Detecciones = @()
    DpsInfo = @{}
    DpsDump = @()
}

# ==========================================
# 3. FUNCIONES DE INTERFAZ Y FORMATEO
# ==========================================

function Show-Banner {
    Clear-Host
    $bannerText = @'
   ██████╗ ███████╗██████╗ ██╗      █████╗  ██████╗███████╗
   ██╔══██╗██╔════╝██╔══██╗██║     ██╔══██╗██╔════╝██╔════╝
   ██████╔╝█████╗  ██████╔╝██║     ███████║██║     █████╗  
   ██╔══██╗██╔══╝  ██╔═══╝ ██║     ██╔══██║██║     ██╔══╝  
   ██║  ██║███████╗██║     ███████╗██║  ██║╚██████╗███████╗
   ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝╚══════╝
            REPLACE FINDER v2.0 - SCREENSHARE FORENSICS
            [ Explorer | Copy 1 | Copy 2 | Type 1 | Type 2 ]
            [ DPS Memory Dump: Regex !! y .exe | PE Headers ]
'@
    Write-Host $bannerText -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor DarkGray
    Write-Host " Usuario: $env:USERNAME@$env:COMPUTERNAME | Hora: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkCyan
    if ($isAdmin) {
        Write-Host " Permisos: [ADMINISTRADOR] - Acceso completo a USN Journal y Proceso DPS" -ForegroundColor Green
    } else {
        Write-Host " Permisos: [NO ELEVADO] - Requiere Administrador para leer USN Journal y DPS" -ForegroundColor Red
    }
    Write-Host "================================================================================" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-Menu {
    Show-Banner
    Write-Host " SELECCIONA UNA OPCION:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host " [1] Escanear Todo (USN Journal + Proceso DPS + Deteccion Global)" -ForegroundColor White
    Write-Host " [2] Buscar Replaces en una Ruta Especifica (e.g. .minecraft, mods)" -ForegroundColor White
    Write-Host " [3] Analisis y DUMP Forense de DPS (Regex !!, .exe y Fecha Compilacion PE)" -ForegroundColor White
    Write-Host " [4] Ver Tabla de Firmas y Motivos (Explorer, Copy1, Copy2, Type1, Type2)" -ForegroundColor White
    Write-Host " [5] Exportar Ultimo Reporte a Archivo de Texto (.txt)" -ForegroundColor White
    Write-Host " [6] Salir" -ForegroundColor DarkGray
    Write-Host ""
}

# ==========================================
# 4. MODULO FORENSE DE AUDITORIA Y DUMP DE DPS
# ==========================================
function Invoke-DpsAudit {
    param([string]$customKeyword = "")

    Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " [***] AUDITORIA FORENSE Y DUMP DEL PROCESO DPS (Diagnostic Policy Service) [***]" -ForegroundColor Cyan
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Cyan

    $dpsStatus = @{
        ServiceRunning = $false
        TamperDetected = $false
        HostPid = 0
        Entries = @()
    }

    # 1. Estado del servicio DPS
    $svc = Get-Service -Name "DPS" -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq 'Running') {
            Write-Host " [+] Estado del Servicio DPS: " -NoNewline
            Write-Host "EN EJECUCION (Running)" -ForegroundColor Green
            $dpsStatus.ServiceRunning = $true
        } else {
            Write-Host " [!] ALERTA CRITICA: " -NoNewline -ForegroundColor Red
            Write-Host "El servicio DPS esta DETENIDO o DESHABILITADO ($($svc.Status))" -ForegroundColor Red
            Write-Host "     Posible intento de evadir el registro de ejecuciones/actividad." -ForegroundColor Yellow
        }
    } else {
        Write-Host " [!] No se pudo obtener el estado del servicio DPS." -ForegroundColor Red
    }

    # 2. Host Process y Tampering / Uptime Check
    $dpsWmi = Get-CimInstance Win32_Service -Filter "Name='DPS'" -ErrorAction SilentlyContinue
    if ($dpsWmi -and $dpsWmi.ProcessId -gt 0) {
        $pidNum = $dpsWmi.ProcessId
        $dpsStatus.HostPid = $pidNum
        Write-Host " [+] Proceso Anfitrion (svchost.exe): PID $pidNum" -ForegroundColor Gray

        $proc = Get-Process -Id $pidNum -ErrorAction SilentlyContinue
        if ($proc -and $proc.StartTime) {
            $bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
            $systemUptimeMin = [math]::Round(((Get-Date) - $bootTime).TotalMinutes, 1)
            $dpsUptimeMin = [math]::Round(((Get-Date) - $proc.StartTime).TotalMinutes, 1)

            # Si el sistema lleva mas de 25 min encendido pero DPS arranco hace menos de 15 min
            if ($systemUptimeMin -gt 25 -and $dpsUptimeMin -lt 15) {
                Write-Host " [!] ALERTA CRITICA: " -NoNewline -ForegroundColor Red
                Write-Host "El proceso DPS fue REINICIADO recientemente ($($dpsUptimeMin) min)." -ForegroundColor Red
                Write-Host "     El sistema lleva activo $($systemUptimeMin) min. Posible reinicio para borrar memoria." -ForegroundColor Yellow
                $dpsStatus.TamperDetected = $true
            } else {
                Write-Host " [+] Tiempo de Actividad DPS: Estable ($($dpsUptimeMin) min, coherente con el inicio del sistema)." -ForegroundColor Green
            }
        }
    }

    # 3. DUMP DE MEMORIA DEL PROCESO DPS CON REGEX !! Y .EXE
    Write-Host "`n [*] Dumpeando memoria del proceso DPS con regex '!!' y '.exe'..." -ForegroundColor Yellow
    Write-Host "     Extrayendo rutas, cabeceras PE y fechas de compilacion..." -ForegroundColor DarkGray

    if ($dpsStatus.HostPid -gt 0) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $dumpEntries = [ReplaceFinder.DpsScanner]::DumpProcessRegex($dpsStatus.HostPid, $customKeyword)
        $sw.Stop()

        $dpsStatus.Entries = $dumpEntries
        $global:UltimoReporte.DpsDump = $dumpEntries

        Write-Host " [+] Dump finalizado en $($sw.Elapsed.TotalSeconds.ToString('0.00')) s. Entradas encontradas: $($dumpEntries.Count)" -ForegroundColor Green

        $suspiciousEntries = @($dumpEntries | Where-Object { $_.IsSuspicious })
        $normalEntries = @($dumpEntries | Where-Object { -not $_.IsSuspicious })

        Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host " [***] EJECUTABLES CON ANOMALIAS O INCONSISTENCIAS DE FECHA/TIMESTOMP [***]" -ForegroundColor Cyan
        Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Cyan

        if ($suspiciousEntries.Count -gt 0) {
            Write-Host " [!] SE DETECTARON $($suspiciousEntries.Count) EJECUTABLES SOSPECHOSOS EN DPS:" -ForegroundColor Red
            Write-Host ""
            foreach ($e in $suspiciousEntries) {
                Write-Host " [!] ALERTA: $($e.FileName)" -ForegroundColor Red
                Write-Host "     [-] Cadena DPS:        $($e.RawString)" -ForegroundColor DarkGray
                Write-Host "     [-] Ruta Completa:     $($e.ExePath)" -ForegroundColor White
                Write-Host "     [-] Fecha Compilacion: $($e.CompileDate)" -ForegroundColor Yellow
                Write-Host "     [-] Creacion en Disco: $($e.CreationDate)" -ForegroundColor DarkCyan
                Write-Host "     [-] Modificado Disco:  $($e.LastWriteDate)" -ForegroundColor DarkCyan
                Write-Host "     [-] Estado Forense:    $($e.Status)" -ForegroundColor Red
                Write-Host ""
            }
        } else {
            Write-Host " [+] No se detectaron timestomps ni ejecutables borrados en las cadenas de DPS." -ForegroundColor Green
        }

        # Preguntar si desea ver todos los ejecutables encontrados
        if ($normalEntries.Count -gt 0) {
            Write-Host " [*] Se encontraron $($normalEntries.Count) ejecutables legitimos/coherentes en DPS." -ForegroundColor Gray
            $verTodos = Read-Host " Deseas listar todos los ejecutables normales encontrados en DPS? (S/N)"
            if ($verTodos -eq 'S' -or $verTodos -eq 's') {
                Write-Host ""
                foreach ($e in $normalEntries) {
                    Write-Host " [+] $($e.FileName)" -ForegroundColor Green
                    Write-Host "     Compilacion PE: $($e.CompileDate) | Creacion: $($e.CreationDate)" -ForegroundColor DarkGray
                    Write-Host "     Ruta: $($e.ExePath)" -ForegroundColor Gray
                }
            }
        }
    } else {
        Write-Host " [!] No se pudo adjuntar al proceso DPS (Requiere permisos de Administrador)." -ForegroundColor Red
    }

    return $dpsStatus
}

# ==========================================
# 5. MODULO DE ESCANEO COMPLETO (OPCION 1)
# ==========================================
function Invoke-FullScan {
    Show-Banner
    Write-Host " [1] ESCANEO COMPLETO DEL SISTEMA" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor DarkGray

    $drive = Read-Host " Ingrese la letra de unidad a analizar (Presione ENTER para 'C:')"
    if ([string]::IsNullOrWhiteSpace($drive)) { $drive = "C:" }
    if (!$drive.EndsWith(":")) { $drive = "$drive`:" }

    Write-Host "`n [*] Analizando NTFS USN Journal en $drive..." -ForegroundColor Yellow
    Write-Host "     Buscando firmas: Explorer, Copy 1, Copy 2, Type 1, Type 2..." -ForegroundColor DarkGray

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $detections = [ReplaceFinder.UsnAnalyzer]::AnalyzeJournal($drive, $null, 0)
    $sw.Stop()

    Write-Host " [+] Analisis de USN Journal finalizado en $($sw.Elapsed.TotalSeconds.ToString('0.00')) segundos." -ForegroundColor Green
    Write-Host "     Total de eventos con firma de Replace: $($detections.Count)" -ForegroundColor Gray

    # Separar en Alta Prioridad y Sistema
    $highPriority = @($detections | Where-Object { $_.IsHighPriority })

    Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " [***] REPLACES DETECTADOS EN ARCHIVOS (.jar, .exe, .dll, etc.) [***]" -ForegroundColor Cyan
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Cyan

    if ($highPriority.Count -gt 0) {
        Write-Host " [!] SE DETECTARON $($highPriority.Count) REEMPLAZOS SOSPECHOSOS:" -ForegroundColor Red
        Write-Host ""
        foreach ($d in $highPriority) {
            Write-Host " [!] REPLACE DETECTADO:" -ForegroundColor Red
            Write-Host "     [-] Archivo:           $($d.FileName)" -ForegroundColor White
            Write-Host "     [-] Tipo de Replace:   " -NoNewline -ForegroundColor White
            Write-Host "$($d.DetectedType)" -ForegroundColor Red
            Write-Host "     [-] Detalle:           $($d.Details)" -ForegroundColor Yellow
            Write-Host "     [-] ID de Archivo:     $($d.FileId)" -ForegroundColor DarkGray
            Write-Host "     [-] Secuencia Motivos: $($d.ReasonSequence)" -ForegroundColor DarkCyan
            Write-Host ""
        }
    } else {
        Write-Host " [+] LIMPIO: No se detectaron reemplazos sospechosos en ejecutables o mods de juego." -ForegroundColor Green
    }

    # Auditoria y Dump del proceso DPS
    $dpsResult = Invoke-DpsAudit

    # Guardar en reporte global
    $global:UltimoReporte.TipoEscaneo = "Escaneo Completo ($drive)"
    $global:UltimoReporte.Fecha = (Get-Date)
    $global:UltimoReporte.Detecciones = $highPriority
    $global:UltimoReporte.DpsInfo = $dpsResult

    # Resumen Final
    Write-Host "`n================================================================================" -ForegroundColor DarkGray
    Write-Host " RESUMEN DEL ESCANEO GLOBAL:" -ForegroundColor Yellow
    $hasDpsSusp = ($dpsResult.Entries | Where-Object { $_.IsSuspicious }).Count -gt 0
    if ($highPriority.Count -gt 0 -or $dpsResult.TamperDetected -or $hasDpsSusp) {
        Write-Host " RESULTADO FINAL: " -NoNewline
        Write-Host "[ SOSPECHOSO / REPLACES O INCONSISTENCIAS DETECTADAS ]" -ForegroundColor Red
    } else {
        Write-Host " RESULTADO FINAL: " -NoNewline
        Write-Host "[ LIMPIO / NO SE DETECTARON ANOMALIAS ]" -ForegroundColor Green
    }
    Write-Host "================================================================================" -ForegroundColor DarkGray
    Write-Host ""
    Pause
}

# ==========================================
# 6. MODULO DE BUSQUEDA EN RUTA ESPECIFICA (OPCION 2)
# ==========================================
function Invoke-PathScan {
    Show-Banner
    Write-Host " [2] BUSCAR REPLACES EN UNA RUTA ESPECIFICA" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor DarkGray

    $defaultPath = "$env:APPDATA\.minecraft"
    Write-Host " Ingrese la ruta de la carpeta a examinar." -ForegroundColor Gray
    Write-Host " (Presione ENTER para usar por defecto: $defaultPath)" -ForegroundColor DarkCyan
    $targetPath = Read-Host " Ruta"
    if ([string]::IsNullOrWhiteSpace($targetPath)) { $targetPath = $defaultPath }

    if (-not (Test-Path $targetPath)) {
        Write-Host "`n [!] La ruta '$targetPath' no existe o no es accesible." -ForegroundColor Red
        Pause
        return
    }

    Write-Host "`n [*] Indexando archivos en '$targetPath'..." -ForegroundColor Yellow
    $files = Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue
    $fileNames = @($files | Select-Object -ExpandProperty Name | Sort-Object -Unique)
    Write-Host " [+] Se encontraron $($fileNames.Count) archivos unicos en la carpeta." -ForegroundColor Green

    $drive = (Get-Item $targetPath).PSDrive.Name + ":"
    Write-Host " [*] Buscando rastros de reemplazo en el USN Journal de la unidad $drive..." -ForegroundColor Yellow

    $detections = [ReplaceFinder.UsnAnalyzer]::AnalyzeJournal($drive, $fileNames, 0)

    # Tambien auditar DPS buscando el nombre de la carpeta
    $folderName = Split-Path $targetPath -Leaf
    $dpsResult = Invoke-DpsAudit -customKeyword $folderName

    Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " [***] RESULTADOS PARA LA RUTA: $targetPath [***]" -ForegroundColor Cyan
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Cyan

    if ($detections.Count -gt 0) {
        Write-Host " [!] ATENCION: Se detectaron $($detections.Count) reemplazos en los archivos de esta ruta:" -ForegroundColor Red
        Write-Host ""
        foreach ($d in $detections) {
            Write-Host " [!] REPLACE CONFIRMADO:" -ForegroundColor Red
            Write-Host "     [-] Archivo:           $($d.FileName)" -ForegroundColor White
            Write-Host "     [-] Tipo de Replace:   " -NoNewline -ForegroundColor White
            Write-Host "$($d.DetectedType)" -ForegroundColor Red
            Write-Host "     [-] Detalle Tecnico:   $($d.Details)" -ForegroundColor Yellow
            Write-Host "     [-] ID de Archivo:     $($d.FileId)" -ForegroundColor DarkGray
            Write-Host "     [-] Secuencia USN:     $($d.ReasonSequence)" -ForegroundColor DarkCyan
            Write-Host ""
        }
    } else {
        Write-Host " [+] LIMPIO: Ningun archivo dentro de '$targetPath' fue reemplazado." -ForegroundColor Green
        Write-Host "     No se hallaron firmas de Explorer, Copy 1, Copy 2, Type 1 ni Type 2." -ForegroundColor DarkGreen
    }

    # Guardar en reporte global
    $global:UltimoReporte.TipoEscaneo = "Escaneo de Ruta ($targetPath)"
    $global:UltimoReporte.Fecha = (Get-Date)
    $global:UltimoReporte.Detecciones = $detections
    $global:UltimoReporte.DpsInfo = $dpsResult

    Write-Host "`n================================================================================" -ForegroundColor DarkGray
    Write-Host ""
    Pause
}

# ==========================================
# 7. MODULO DE TABLA DE FIRMAS (OPCION 4)
# ==========================================
function Show-SignaturesTable {
    Show-Banner
    Write-Host " [4] DICCIONARIO DE FIRMAS Y TIPOS DE REPLACE" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor DarkGray

    Write-Host "`n1. EXPLORER (Reemplazo via Explorador de Windows):" -ForegroundColor White
    Write-Host "   File Delete | Close" -ForegroundColor DarkGray
    Write-Host "   Rename: old name" -ForegroundColor DarkGray
    Write-Host "   Rename: new name" -ForegroundColor DarkGray
    Write-Host "   Rename: new name | Close" -ForegroundColor Yellow
    Write-Host "   -> Ocurre cuando un usuario arrastra o sobrescribe un archivo usando Explorer.exe." -ForegroundColor DarkCyan

    Write-Host "`n2. TYPE 1:" -ForegroundColor White
    Write-Host "   Data Extend | Data Truncation" -ForegroundColor DarkGray
    Write-Host "   Data Extend | Data Truncation | Close" -ForegroundColor Yellow
    Write-Host "   -> Firma de cierre exacta: 0x80000006." -ForegroundColor DarkCyan

    Write-Host "`n3. TYPE 2:" -ForegroundColor White
    Write-Host "   Data Truncation" -ForegroundColor DarkGray
    Write-Host "   Data Extend | Data Truncation" -ForegroundColor Yellow
    Write-Host "   -> Sobrescritura directa de stream sin eventos de Security Change." -ForegroundColor DarkCyan

    Write-Host "`n4. COPY 1:" -ForegroundColor White
    Write-Host "   Data Truncation | Security Change" -ForegroundColor DarkGray
    Write-Host "   Data Extend | Data Truncation | Security Change" -ForegroundColor DarkGray
    Write-Host "   Data Overwrite | Data Extend | Data Truncation | Security Change" -ForegroundColor DarkGray
    Write-Host "   Data Overwrite | Data Extend | Data Truncation | Security Change | Basic Info Change" -ForegroundColor DarkGray
    Write-Host "   Data Overwrite | Data Extend | Data Truncation | Security Change | Basic Info Change | Close" -ForegroundColor Red
    Write-Host "   -> Firma de cierre exacta: 0x80008807 (Incluye Security Change)." -ForegroundColor DarkCyan

    Write-Host "`n5. COPY 2:" -ForegroundColor White
    Write-Host "   Data Truncation" -ForegroundColor DarkGray
    Write-Host "   Data Extend | Data Truncation" -ForegroundColor DarkGray
    Write-Host "   Data Overwrite | Data Extend | Data Truncation" -ForegroundColor DarkGray
    Write-Host "   Data Overwrite | Data Extend | Data Truncation | Basic Info Change" -ForegroundColor DarkGray
    Write-Host "   Data Overwrite | Data Extend | Data Truncation | Basic Info Change | Close" -ForegroundColor Red
    Write-Host "   -> Firma de cierre exacta: 0x80008007 (Sin Security Change)." -ForegroundColor DarkCyan

    Write-Host "`n6. AUDITORIA DPS (Regex !! y .exe):" -ForegroundColor White
    Write-Host "   - Extrae cadenas con regex !! y .exe de la memoria del proceso DPS." -ForegroundColor DarkGray
    Write-Host "   - Resuelve rutas absolutas y de dispositivo (\Device\HarddiskVolumeX)." -ForegroundColor DarkGray
    Write-Host "   - Lee la fecha de compilacion directa de la cabecera PE (TimeDateStamp)." -ForegroundColor Yellow
    Write-Host "   - Compara Fecha Compilacion vs Creacion/Modificacion para detectar Timestomp." -ForegroundColor Yellow

    Write-Host "`n================================================================================" -ForegroundColor DarkGray
    Write-Host ""
    Pause
}

# ==========================================
# 8. MODULO DE EXPORTACION DE REPORTE (OPCION 5)
# ==========================================
function Export-Report {
    Show-Banner
    Write-Host " [5] EXPORTAR REPORTE FORENSE A ARCHIVO" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor DarkGray

    if ($global:UltimoReporte.TipoEscaneo -eq "Ninguno" -and $global:UltimoReporte.DpsDump.Count -eq 0) {
        Write-Host " [!] No hay ningun escaneo previo en memoria para exportar." -ForegroundColor Yellow
        Write-Host "     Realiza primero un escaneo (Opcion 1, 2 o 3)." -ForegroundColor Gray
        Pause
        return
    }

    $timestamp = (Get-Date -Format "yyyyMMdd_HHmmss")
    $exportPath = Join-Path $env:USERPROFILE "Desktop\ReplaceFinder_Report_$timestamp.txt"

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("================================================================================")
    [void]$sb.AppendLine("                 REPORTE FORENSE - REPLACE FINDER v2.0")
    [void]$sb.AppendLine("================================================================================")
    [void]$sb.AppendLine("Fecha:            $($global:UltimoReporte.Fecha)")
    [void]$sb.AppendLine("Operador:         $env:USERNAME")
    [void]$sb.AppendLine("Equipo:           $env:COMPUTERNAME")
    [void]$sb.AppendLine("Tipo de Escaneo:  $($global:UltimoReporte.TipoEscaneo)")
    [void]$sb.AppendLine("================================================================================")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine(">>> DETECCIONES DE REPLACES EN USN JOURNAL <<<")

    if ($global:UltimoReporte.Detecciones.Count -gt 0) {
        foreach ($d in $global:UltimoReporte.Detecciones) {
            [void]$sb.AppendLine("[!] REPLACE DETECTADO:")
            [void]$sb.AppendLine("    Archivo:           $($d.FileName)")
            [void]$sb.AppendLine("    Tipo:              $($d.DetectedType)")
            [void]$sb.AppendLine("    Detalle:           $($d.Details)")
            [void]$sb.AppendLine("    ID de Archivo:     $($d.FileId)")
            [void]$sb.AppendLine("    Secuencia Motivos: $($d.ReasonSequence)")
            [void]$sb.AppendLine("")
        }
    } else {
        [void]$sb.AppendLine("[+] Limpio: No se registraron reemplazos sospechosos en USN Journal.")
        [void]$sb.AppendLine("")
    }

    [void]$sb.AppendLine(">>> ESTADO DE AUDITORIA DPS <<<")
    [void]$sb.AppendLine("Servicio Activo:      $($global:UltimoReporte.DpsInfo.ServiceRunning)")
    [void]$sb.AppendLine("Reinicio Detectado:   $($global:UltimoReporte.DpsInfo.TamperDetected)")
    [void]$sb.AppendLine("PID svchost:          $($global:UltimoReporte.DpsInfo.HostPid)")
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine(">>> DUMP DE EJECUTABLES EN DPS (Regex !!, .exe & PE Headers) <<<")
    if ($global:UltimoReporte.DpsDump.Count -gt 0) {
        foreach ($e in $global:UltimoReporte.DpsDump) {
            [void]$sb.AppendLine("[-] Archivo:           $($e.FileName)")
            [void]$sb.AppendLine("    Cadena DPS:        $($e.RawString)")
            [void]$sb.AppendLine("    Ruta:              $($e.ExePath)")
            [void]$sb.AppendLine("    Compilacion PE:    $($e.CompileDate)")
            [void]$sb.AppendLine("    Creacion Disco:    $($e.CreationDate)")
            [void]$sb.AppendLine("    Modificado Disco:  $($e.LastWriteDate)")
            [void]$sb.AppendLine("    Estado:            $($e.Status)")
            [void]$sb.AppendLine("")
        }
    } else {
        [void]$sb.AppendLine("[+] No hay registros en el dump de DPS.")
    }

    [void]$sb.AppendLine("========================== FIN DEL REPORTE ==========================")

    try {
        [System.IO.File]::WriteAllText($exportPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
        Write-Host " [+] Reporte exportado exitosamente a:" -ForegroundColor Green
        Write-Host "     $exportPath" -ForegroundColor White
    } catch {
        Write-Host " [!] Error al guardar el reporte: $_" -ForegroundColor Red
    }

    Write-Host ""
    Pause
}

# ==========================================
# 9. BUCLE PRINCIPAL DE EJECUCION
# ==========================================
do {
    Show-Menu
    $opcion = Read-Host " Ingrese opcion [1-6]"
    switch ($opcion) {
        "1" { Invoke-FullScan }
        "2" { Invoke-PathScan }
        "3" { 
            Show-Banner
            $null = Invoke-DpsAudit
            Pause
        }
        "4" { Show-SignaturesTable }
        "5" { Export-Report }
        "6" { 
            Write-Host "`n Saliendo de Replace Finder... Hasta luego!" -ForegroundColor DarkGray
            break
        }
        default {
            Write-Host " Opcion no valida. Intente nuevamente." -ForegroundColor Red
            Start-Sleep -Milliseconds 800
        }
    }
} while ($opcion -ne "6")
