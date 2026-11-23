# 🛡️ Laboratorio Blue Team: Wazuh + Sysmon + Atomic Red Team

Laboratorio de **Detection Engineering** en el que se simulan seis técnicas de MITRE ATT&CK contra un endpoint Windows monitorizado con Wazuh. Se evalúa qué detecta Wazuh de serie, se identifican huecos de cobertura y se desarrollan reglas propias cuando resulta adecuado.

> El objetivo no es solo desplegar un SIEM: es validar detecciones con pruebas controladas, analizar resultados y documentar tanto los aciertos como las limitaciones.

## 📌 Objetivos

- Desplegar un entorno aislado de monitorización.
- Simular técnicas de ataque con Atomic Red Team y Hydra.
- Evaluar la cobertura de las reglas de Wazuh.
- Crear y validar reglas locales para cubrir detecciones incompletas.
- Documentar falsos positivos, huecos y oportunidades de mejora.

## ⚙️ Tecnologías

| Tecnología | Uso |
|---|---|
| Wazuh 4.14.10 (OVA) | SIEM: manager, indexer y dashboard |
| Sysmon | Telemetría de Windows, configuración de SwiftOnSecurity |
| Atomic Red Team | Simulación de técnicas MITRE ATT&CK |
| Hydra | Pruebas controladas de fuerza bruta RDP desde Kali Linux |
| VirtualBox | Virtualización del laboratorio |

## 🧩 Arquitectura

```text
Red Host-only: 192.168.56.0/24

┌─────────────────┐     RDP / 3389     ┌──────────────────────┐
│    Kali Linux   │ ─────────────────▶ │      Windows 10      │
│ Hydra           │                    │ Agente Wazuh          │
│ Atacante        │                    │ Sysmon                │
└─────────────────┘                    │ Atomic Red Team       │
                                       └──────────┬───────────┘
                                                  │ Eventos 1514/1515
                                                  ▼
                                       ┌──────────────────────┐
                                       │      Wazuh OVA      │
                                       │ Manager / Indexer   │
                                       │ Dashboard            │
                                       └──────────┬───────────┘
                                                  │ HTTPS / 443
                                                  ▼
                                       Portátil / navegador
```

Todas las VMs disponen además de un adaptador NAT para salida a Internet y descargas. La red de laboratorio utiliza un adaptador **Solo anfitrión (Host-only)** de VirtualBox.

### Máquinas virtuales

| VM | Rol | Sistema operativo | Recursos | Software |
|---|---|---|---|---|
| `wazuh-ova` | SIEM | Amazon Linux 2023 (OVA de Wazuh) | 4 CPU, 8 GB RAM, 50 GB disco | Wazuh 4.14.10 |
| Windows 10 | Víctima | Windows 10 | 2 CPU, 4 GB RAM | Agente Wazuh, Sysmon, Atomic Red Team |
| Kali Linux | Atacante | Kali Linux | 2 CPU, 4 GB RAM | Hydra |

## 📁 Estructura del repositorio

```text
wazuh-attack-simulation-lab/
├── README.md
├── rules/
│   └── local_rules.xml
├── evidence/
│   ├── ciclo1-powershell-encoded/
│   ├── ciclo2-rdp-bruteforce/
│   ├── ciclo3-scheduled-task/
│   ├── ciclo4-registry-run-key/
│   ├── ciclo5-local-account/
│   └── ciclo6-log-clearing/
└── docs/
    ├── arquitectura.png
    └── dashboard-overview.png
```

## 🛠️ Instalación y configuración

### 1. Wazuh OVA

Importar la OVA oficial en VirtualBox. Configuración recomendada del laboratorio:

- Controlador gráfico: **VMSVGA**
- Reloj del sistema: UTC
- Adaptador 1: NAT
- Adaptador 2: Solo anfitrión

Si los servicios quedan detenidos tras reiniciar:

```bash
sudo systemctl start wazuh-indexer
sudo systemctl start wazuh-manager
sudo systemctl start filebeat
sudo systemctl start wazuh-dashboard
```

### 2. Sysmon en Windows

Descargar la configuración de SwiftOnSecurity:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\sysmonconfig-export.xml"
Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig-export.xml
```

### 3. Agente Wazuh

Desde **Endpoints Summary → Deploy new agent**, seleccionar Windows MSI, introducir la IP del manager y el nombre del agente. Después, añadir a `ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### 4. Atomic Red Team

Preparar Atomic Red Team en la VM Windows de laboratorio:

```powershell
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

> ⚠️ **Seguridad:** las pruebas pueden ser detectadas o bloqueadas por Microsoft Defender. Utiliza únicamente una VM aislada y dedicada. No desactives la protección ni añadas exclusiones en equipos reales o de producción; limita cualquier excepción a lo estrictamente necesario en el laboratorio.

## 🔍 Reglas personalizadas

Archivo: `rules/local_rules.xml`

| Rule ID | Ciclo | MITRE ATT&CK | Nivel | Propósito |
|---|---|---|---:|---|
| `100100` | 1 | T1059.001 | 12 | Detectar PowerShell con `-EncodedCommand`/abreviaturas y bloque Base64, sin depender del proceso padre |
| `100102` | 4 | T1547.001 | 6 | Detectar modificación de la clave Run mediante PowerShell |

### Regla 100100 — PowerShell con Base64

La regla amplía la cobertura de la regla de serie `92057`, que no detectaba algunas abreviaturas ni todos los procesos padre probados.

```xml
<group name="local,sysmon,powershell,">
  <rule id="100100" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\s[-/](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+[A-Za-z0-9+/=]{16,}</field>
    <description>PowerShell con comando codificado en Base64 (cualquier abreviatura de -EncodedCommand y cualquier proceso padre)</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>
</group>
```

### Regla 100102 — Persistencia mediante clave Run

La familia de reglas `92300–92303` cubría `reg.exe`, pero no la escritura equivalente mediante PowerShell (`New-ItemProperty`). La regla propia amplía la detección a ese método.

```xml
<group name="local,sysmon,registry,">
  <rule id="100102" level="6">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)(powershell|pwsh)\.exe</field>
    <description>Registry entry to be executed on next logon was modified using PowerShell</description>
    <mitre><id>T1547.001</id></mitre>
  </rule>
</group>
```

Validar y desplegar las reglas:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

## 📊 Dashboard de Wazuh

Filtro para los eventos del endpoint:

```text
agent.name: "WIN10-LAB"
```

Filtro para las reglas propias:

```text
rule.id: (100100 or 100102)
```

### Métricas del laboratorio

| Métrica | Resultado |
|---|---:|
| Alertas totales generadas | 8.752 |
| Alertas de nivel 12 o superior | 617 |
| Autenticaciones fallidas (ciclo 2) | 36 |
| Autenticaciones exitosas | 13 |

## 🧪 Resultados por técnica MITRE ATT&CK

| Ciclo | Técnica | Prueba | Detección de serie | Regla propia | Resultado |
|---:|---|---|---|---|---|
| 1 | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Variantes de `-EncodedCommand` y distintos procesos padre | Parcial: algunas abreviaturas y `cmd.exe` no se detectaban | `100100` | Cobertura ampliada, nivel 12 |
| 2 | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Hydra contra RDP: rápido y espaciado (45 s) | Parcial: solo ataque rápido | No implementada | Hueco documentado |
| 3 | [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | Creación y ejecución con `schtasks` | Sí, pero genérico/mal etiquetado | No implementada | Detectado, mal etiquetado |
| 4 | [T1547.001 — Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/) | `reg.exe` frente a `New-ItemProperty` | Parcial: cubría `reg.exe` | `100102` | Cobertura ampliada, nivel 6 |
| 5 | [T1136.001 — Local Account](https://attack.mitre.org/techniques/T1136/001/) | `net user` frente a `New-LocalUser` | Parcial: Sysmon detecta `net user`; auditoría detecta ambas vías con etiqueta genérica | No implementada | Hueco de detalle documentado |
| 6 | [T1070.001 — Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/) | `wevtutil cl` sobre Seguridad y Sysmon | Sí, independiente de la herramienta | No necesaria | Detectado; nivel bajo |

### Resumen de cobertura

- **2 técnicas** tenían huecos ampliados con reglas propias: ciclos 1 y 4.
- **2 técnicas** quedaron documentadas sin regla propia por el riesgo de falsos positivos: ciclos 2 y 5.
- **1 técnica** reveló un problema de etiquetado MITRE: ciclo 3.
- **1 técnica** mostró detección robusta independiente de la herramienta: ciclo 6.

## 🔎 Hallazgos por ciclo

### Ciclo 1 — PowerShell con Base64 (T1059.001)

La regla de serie `92057` exige un proceso padre `powershell.exe` y una lista limitada de abreviaturas. Con `-ENC` o con el comando lanzado desde `cmd.exe`, solo se generaban alertas de nivel 3–4.

La regla `100100` amplía la cobertura a las abreviaturas probadas, sin depender del proceso padre, y exige un bloque Base64 para reducir confusiones con `-ExecutionPolicy`. Se validó con ocho combinaciones (cuatro abreviaturas y dos procesos padre) y un control negativo.

**Hallazgo colateral:** el lanzamiento de PowerShell también generaba la alerta `92213` (nivel 15), asociada al archivo `__PSScriptPolicyTest_*.ps1` que PowerShell crea al arrancar. Se observó como posible falso positivo de alta severidad.

### Ciclo 2 — Fuerza bruta RDP (T1110.001)

La regla `60204` correlaciona ocho fallos (`60122`) desde una misma IP en una ventana de 240 segundos. Con Hydra a máxima velocidad, 12 intentos dispararon la correlación al octavo fallo. Con 45 segundos entre intentos (`hydra -t 1 -W 45`), los fallos se distribuyeron durante unos nueve minutos y no se alcanzó el umbral.

No se implementó regla propia porque ampliar la ventana y reducir el umbral puede aumentar los falsos positivos.

### Ciclo 3 — Tarea programada (T1053.005)

La creación (`schtasks /create`) y la ejecución posterior generaron alertas, pero no se etiquetaron como `T1053.005`. La ejecución se detectó mediante la regla genérica `92052` (“cmd lanzado por un proceso anormal”), etiquetada como `T1059.003`.

El hallazgo fue de contexto y clasificación: la alerta indicaba un proceso sospechoso, pero no la persistencia mediante tarea programada. No se implementó regla propia porque sería necesario correlacionar la creación y ejecución en el tiempo.

### Ciclo 4 — Clave Run del registro (T1547.001)

Wazuh dispone de reglas específicas (`92300–92303`), pero la cobertura observada correspondía a `reg.exe` (regla `92302`). La escritura equivalente mediante PowerShell (`New-ItemProperty`) no generaba una alerta visible de nivel relevante, aunque Sysmon identificaba el patrón como `T1060,RunKey`.

La regla `100102` amplía la detección a modificaciones realizadas mediante PowerShell.

### Ciclo 5 — Creación de cuenta local (T1136.001)

Se probaron `net user` y `New-LocalUser`. Sysmon detectó con precisión `net user` mediante la regla `92040`, etiquetada como `T1136.001`, pero no identificó del mismo modo la creación mediante PowerShell.

La auditoría nativa de Windows (eventos `4720`, `4722` y `4738`; reglas `60109–60110`) detectó ambas vías, aunque con una etiqueta genérica `T1098`.

**Conclusión:** la creación de la cuenta no pasó completamente inadvertida, pero con PowerShell se perdió el detalle de la herramienta utilizada.

### Ciclo 6 — Borrado de logs (T1070.001)

Las reglas `63103` (registro de Seguridad, evento `1102`) y `63104` (otros registros, evento `104`) detectaron la limpieza sin depender del proceso. Se probó contra el registro de Seguridad y el de Sysmon; ambos generaron alerta.

El principal matiz fue la severidad: las alertas eran de nivel 5, bajo para una actividad potencialmente importante durante un ataque.

## 🔄 Problemas encontrados

| Problema | Causa | Solución aplicada |
|---|---|---|
| Instalación manual de Wazuh fallaba (`No space left on device`) | Espacio insuficiente | Utilizar la OVA oficial |
| Agente instalado parcialmente, sin `ossec.conf` | Instalación dañada | Desinstalar con `Uninstall-Package` y reinstalar |
| `NET START WazuhSvc` fallaba por `log_format` inválido | Errata `eventchanel` | Corregir a `eventchannel` |
| Atomic Red Team bloqueado (`ScriptContainedMaliciousContent`) | AMSI analiza el script | Preparar el entorno de pruebas aislado y revisar la configuración de protección |
| Dashboard sin eventos recientes | Reloj de Windows desincronizado unas 2 horas | `w32tm /resync /force` tras restaurar snapshots |
| Regla propia no disparaba pese a validar | Espacio en regex y campo incorrecto (`win.event.image` en vez de `win.eventdata.image`) | Validar y probar contra eventos reales |

## ✅ Conclusiones

- Wazuh detecta bien patrones directos, pero la cobertura puede depender de la herramienta utilizada (`reg.exe` frente a PowerShell, por ejemplo).
- La detección más robusta fue el borrado de logs, basado en eventos generados por Windows y no en una herramienta concreta.
- No todos los huecos justifican una regla propia: documentar el riesgo de falsos positivos también es una decisión válida de Detection Engineering.
- Detectar no basta: la etiqueta MITRE debe reflejar la técnica y el nivel de alerta debe ser coherente con su gravedad.

## 🔧 Próximos pasos

1. Afinar las reglas `100100` y `100102` con actividad legítima para evaluar falsos positivos.
2. Investigar una correlación más precisa para los ciclos 2 y 5, con umbrales, ventanas y posibles listas blancas.
3. Crear una regla de persistencia para el ciclo 3 que correlacione creación y ejecución de tareas.
4. Revisar el nivel de las reglas `63103` y `63104` del ciclo 6.
5. Ampliar el laboratorio con técnicas de movimiento lateral y exfiltración, o repetir los ciclos con otros procesos padre.

## 🛠️ Herramientas

- Wazuh — SIEM y correlación de eventos
- Sysmon — Telemetría de Windows
- Atomic Red Team — Simulación de técnicas MITRE ATT&CK
- Hydra — Pruebas controladas de fuerza bruta
- VirtualBox — Virtualización

---

> Todas las pruebas se realizan en un laboratorio virtual aislado y con sistemas bajo control propio.
