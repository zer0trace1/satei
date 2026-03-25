# SATEI

**Judge the risk. Prioritize the threat.**

SATEI es una herramienta CLI orientada a la priorización de vulnerabilidades.  
En su versión actual, permite analizar un CVE concreto y enriquecerlo con información procedente de NVD, EPSS y CISA KEV para ofrecer una prioridad orientativa.

## Características

- Consulta de vulnerabilidades por identificador CVE
- Obtención de descripción y métricas CVSS desde NVD
- Consulta de score EPSS y percentil
- Comprobación de presencia en CISA KEV
- Priorización simple del riesgo:
  - `low`
  - `medium`
  - `high`
  - `critical`
- Salida en terminal
- Salida en formato JSON con `--json`

## Fuentes utilizadas

- **NVD**: información general del CVE y métricas CVSS
- **EPSS (FIRST)**: probabilidad estimada de explotación
- **CISA KEV**: catálogo de vulnerabilidades explotadas activamente

## Requisitos

- Python 3.10+
- Entorno virtual recomendado

## Instalación

Clona el repositorio:

```bash
git clone git@github.com:TU_USUARIO/satei.git
cd satei
```

Crea y activa un entorno virtual:

### Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows PowerShell
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Instala las dependencias:

```bash
pip install -r requirements.txt
```

## Dependencias

El archivo `requirements.txt` debería contener:

```txt
typer
requests
rich
```

## Uso

### Mostrar versión
```bash
python satei.py version
```

### Analizar un CVE
```bash
python satei.py cve CVE-2024-3400
```

### Obtener salida en JSON
```bash
python satei.py cve CVE-2024-3400 --json
```

### Guardar resultado en un fichero JSON
```bash
python satei.py cve CVE-2024-3400 --json > resultado.json
```

## Ejemplo de salida

```text
SATEI → analizando CVE-2024-3400

Prioridad: CRITICAL
Motivo: Incluida en CISA KEV (explotación conocida en el mundo real)
CVSS: 10.0
EPSS: 0.94
In CISA KEV: True
```

## Funcionamiento de la priorización

SATEI aplica una heurística sencilla basada en tres señales principales:

- presencia en **CISA KEV**
- score **EPSS**
- score **CVSS**

Reglas actuales:

- `critical` → si el CVE está incluido en **CISA KEV**
- `high` → si `EPSS >= 0.70` o `CVSS >= 9.0`
- `medium` → si `EPSS >= 0.30` o `CVSS >= 7.0`
- `low` → en el resto de casos

Esta prioridad es **orientativa** y no sustituye un proceso formal de gestión de vulnerabilidades.

## Limitaciones

- Actualmente solo soporta consulta de un **CVE individual**
- La priorización se basa en heurísticas simples
- La disponibilidad y calidad del resultado dependen de las fuentes consultadas
- No incluye aún análisis por lotes ni exportaciones avanzadas

## Roadmap

Versiones futuras de SATEI podrían incluir:

- análisis de múltiples CVE en una sola ejecución
- lectura desde ficheros CSV o TXT
- exportación enriquecida
- salida tabular resumida
- integración con otras fuentes de threat intelligence
- ajuste de pesos/umbrales de priorización

## Estructura actual

```text
satei/
├── satei.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Licencia

MIT License.

## Autor

**Pablo Infante**  
Máster en Ciberseguridad y Ciberinteligencia
