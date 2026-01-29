# 🎯 Threat Hunting Cheatsheet

```
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗██╗███╗   ██╗ ██████╗ 
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝ 
   ██║   ███████║██████╔╝█████╗  ███████║   ██║       ███████║██║   ██║██╔██╗ ██║   ██║   ██║██╔██╗ ██║██║  ███╗
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██║██║╚██╗██║██║   ██║
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║██║ ╚████║╚██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝ 
```

---

## 🎯 Threat Hunting Process

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ 1. HYPOTHESIS│────▶│ 2. COLLECT  │────▶│ 3. ANALYZE  │────▶│ 4. RESPOND  │
│   (Theory)   │     │   (Data)    │     │   (Hunt)    │     │   (Action)  │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                    │
                          ┌─────────────┐                          │
                          │ 5. DOCUMENT │◀─────────────────────────┘
                          │   (Learn)   │
                          └─────────────┘
```

---

## 📋 Hypothesis Examples

| Category | Hypothesis |
|----------|------------|
| **Initial Access** | Attackers may use phishing to deliver malware |
| **Persistence** | Attackers may create scheduled tasks for persistence |
| **Credential** | Attackers may dump LSASS to harvest credentials |
| **Lateral** | Attackers may use RDP to move laterally |
| **Exfiltration** | Attackers may use DNS tunneling to exfil data |

---

## 🔍 Hunting Techniques

### Hunt for Persistence

#### Windows Registry Run Keys
```powershell
# Query all Run keys
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
```

#### Scheduled Tasks
```powershell
# List all scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | 
    Select-Object TaskName, TaskPath, State | Format-Table

# Look for suspicious tasks (non-Microsoft)
Get-ScheduledTask | Where-Object {$_.Author -notlike "*Microsoft*"} | 
    Select-Object TaskName, Author, State
```

#### Services
```powershell
# Non-signed services
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "*Windows*"} | 
    Select-Object Name, PathName, StartMode, State
```

### Hunt for Lateral Movement

#### RDP Connections
```powershell
# RDP sessions (Event 4624 Type 10)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | 
    Where-Object {$_.Properties[8].Value -eq 10} |
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='Source';E={$_.Properties[18].Value}}
```

#### Network Connections
```powershell
# Current connections
Get-NetTCPConnection -State Established | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | 
    Format-Table

# With process names
Get-NetTCPConnection | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        RemoteAddress = $_.RemoteAddress
        RemotePort = $_.RemotePort
        Process = $proc.ProcessName
    }
} | Format-Table
```

### Hunt for Credential Access

#### LSASS Access
```powershell
# Sysmon Event 10 - LSASS access
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=10} |
    Where-Object {$_.Properties[8].Value -like "*lsass.exe"} |
    Select-Object TimeCreated, @{N='Source';E={$_.Properties[4].Value}}
```

### Hunt for Execution

#### Encoded PowerShell
```powershell
# PowerShell with encoding
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4104} |
    Where-Object {$_.Message -match "FromBase64" -or $_.Message -match "-enc"} |
    Select-Object TimeCreated, Message
```

#### Suspicious Parent-Child
```powershell
# Office spawning cmd/powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=1} |
    Where-Object {
        ($_.Properties[20].Value -match "WINWORD|EXCEL|OUTLOOK") -and
        ($_.Properties[4].Value -match "cmd|powershell")
    }
```

---

## 🐧 Linux Threat Hunting

### Persistence
```bash
# Cron jobs
cat /etc/crontab
for user in $(cut -f1 -d: /etc/passwd); do crontab -l -u $user 2>/dev/null; done

# SSH authorized keys
find / -name "authorized_keys" 2>/dev/null

# Startup scripts
ls -la /etc/init.d/
systemctl list-unit-files --type=service | grep enabled

# SUID binaries
find / -perm -4000 -type f 2>/dev/null
```

### Network
```bash
# Listening ports
ss -tulnp
netstat -tulnp

# Established connections
ss -tnp state established
lsof -i -P -n | grep ESTABLISHED

# Unusual DNS
tcpdump -i any port 53 -w dns.pcap
```

### Processes
```bash
# All processes with full command
ps auxwww

# Process tree
pstree -p

# Hidden processes
ps aux | awk '{print $2}' | xargs -I{} ls -la /proc/{}/exe 2>/dev/null

# Recently modified binaries
find /usr/bin /usr/sbin -mtime -7 2>/dev/null
```

---

## 📊 IOC Hunting

### Hash Hunting
```powershell
# Calculate hashes
Get-FileHash -Algorithm SHA256 C:\suspicious.exe

# Search for known bad hash
$badHash = "abc123..."
Get-ChildItem -Path C:\ -Recurse -File | Get-FileHash -Algorithm SHA256 |
    Where-Object {$_.Hash -eq $badHash}
```

### IP/Domain Hunting
```powershell
# DNS cache
Get-DnsClientCache | Where-Object {$_.Name -like "*suspicious*"}

# Connection to known bad IP
Get-NetTCPConnection | Where-Object {$_.RemoteAddress -eq "1.2.3.4"}
```

---

## 🛠️ Tools

| Tool | Purpose |
|------|---------|
| **Velociraptor** | Endpoint hunting at scale |
| **OSQuery** | SQL-based endpoint queries |
| **KAPE** | Triage collection |
| **Chainsaw** | Fast Windows log analysis |
| **DeepBlueCLI** | PowerShell threat hunting |

---

## 📋 Quick Hunt Checklist

```markdown
□ Check autorun locations (registry, services, tasks)
□ Review recent process creation (Event 4688, Sysmon 1)
□ Analyze network connections
□ Look for encoded commands
□ Search for LSASS access
□ Check for unusual parent-child process relationships
□ Review PowerShell logs
□ Look for lateral movement indicators
```

---

## 🔗 Related Cheatsheets

- [Log Analysis](./Log-Analysis.md)
- [SIEM Detection](./SIEM-Detection.md)
- [Sigma Rules](./Sigma-Rules.md)

---

**Previous:** [← SIEM Detection](./SIEM-Detection.md)

**Next:** [Malware Analysis →](./Malware-Analysis.md)
