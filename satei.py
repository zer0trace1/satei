from __future__ import annotations

import re
from typing import Any, Optional

import requests
import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import json
import re
from typing import Any, Optional

app = typer.Typer(
    help="SATEI - CVE prioritization CLI",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
VERSION = "0.1.0"

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

DEFAULT_HEADERS = {
    "User-Agent": "SATEI/0.1 (+https://github.com/your-user/satei)",
    "Accept": "application/json",
}

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def validate_cve(value: str) -> str:
    cve_id = value.strip().upper()
    if not CVE_PATTERN.match(cve_id):
        raise typer.BadParameter("Introduce un CVE válido, por ejemplo: CVE-2024-3400")
    return cve_id


def safe_get(url: str, *, params: Optional[dict[str, Any]] = None) -> requests.Response:
    response = requests.get(
        url,
        params=params,
        headers=DEFAULT_HEADERS,
        timeout=20,
    )
    response.raise_for_status()
    return response


def fetch_nvd_cve(cve_id: str) -> dict[str, Any]:
    response = safe_get(NVD_CVE_API_URL, params={"cveId": cve_id})
    payload = response.json()
    vulnerabilities = payload.get("vulnerabilities", [])

    if not vulnerabilities:
        raise ValueError(f"No se encontró información en NVD para {cve_id}")

    return vulnerabilities[0].get("cve", {})


def fetch_epss(cve_id: str) -> Optional[dict[str, Any]]:
    response = safe_get(EPSS_API_URL, params={"cve": cve_id})
    payload = response.json()

    data = payload.get("data", [])
    if not data:
        return None

    return data[0]


def fetch_kev_entry(cve_id: str) -> Optional[dict[str, Any]]:
    response = safe_get(CISA_KEV_JSON_URL)
    payload = response.json()

    vulnerabilities = payload.get("vulnerabilities", [])
    for item in vulnerabilities:
        if str(item.get("cveID", "")).upper() == cve_id.upper():
            return item

    return None


def extract_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "No description available.")
    if descriptions:
        return descriptions[0].get("value", "No description available.")
    return "No description available."


def extract_cvss(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get("metrics", {})

    candidates = [
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]

    for key, version in candidates:
        entries = metrics.get(key)
        if not entries:
            continue

        preferred = next((entry for entry in entries if entry.get("type") == "Primary"), entries[0])
        cvss_data = preferred.get("cvssData", {})

        return {
            "version": version,
            "base_score": cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity") or preferred.get("baseSeverity"),
            "vector": cvss_data.get("vectorString"),
            "source": preferred.get("source"),
        }

    return {
        "version": None,
        "base_score": None,
        "severity": None,
        "vector": None,
        "source": None,
    }


def calculate_priority(
    *,
    cvss_score: Optional[float],
    epss_score: Optional[float],
    in_kev: bool,
) -> tuple[str, str]:
    if in_kev:
        return "critical", "Incluida en CISA KEV (explotación conocida en el mundo real)"

    if epss_score is not None and epss_score >= 0.70:
        return "high", "EPSS alto"

    if cvss_score is not None and cvss_score >= 9.0:
        return "high", "CVSS muy alto"

    if epss_score is not None and epss_score >= 0.30:
        return "medium", "EPSS moderado"

    if cvss_score is not None and cvss_score >= 7.0:
        return "medium", "CVSS alto"

    return "low", "Sin señales fuertes de priorización"

def build_output_payload(
    *,
    cve_id: str,
    priority: str,
    reason: str,
    nvd_cve: dict[str, Any],
    description: str,
    cvss: dict[str, Any],
    epss_data: Optional[dict[str, Any]],
    kev_entry: Optional[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "tool": "SATEI",
        "version": VERSION,
        "query": {
            "type": "cve",
            "value": cve_id,
        },
        "verdict": {
            "priority": priority,
            "reason": reason,
        },
        "nvd": {
            "id": nvd_cve.get("id"),
            "status": nvd_cve.get("vulnStatus"),
            "published": nvd_cve.get("published"),
            "last_modified": nvd_cve.get("lastModified"),
            "description": description,
            "cvss": {
                "version": cvss.get("version"),
                "base_score": cvss.get("base_score"),
                "severity": cvss.get("severity"),
                "vector": cvss.get("vector"),
                "source": cvss.get("source"),
            },
        },
        "epss": {
            "score": epss_data.get("epss") if epss_data else None,
            "percentile": epss_data.get("percentile") if epss_data else None,
            "date": (
                epss_data.get("date", epss_data.get("created"))
                if epss_data
                else None
            ),
        },
        "kev": {
            "in_kev": bool(kev_entry),
            "vendor": kev_entry.get("vendorProject") if kev_entry else None,
            "product": kev_entry.get("product") if kev_entry else None,
            "date_added": kev_entry.get("dateAdded") if kev_entry else None,
            "due_date": kev_entry.get("dueDate") if kev_entry else None,
            "known_ransomware_use": (
                kev_entry.get("knownRansomwareCampaignUse")
                if kev_entry
                else None
            ),
            "notes": kev_entry.get("notes") if kev_entry else None,
        },
    }

def make_summary_table(
    cve_id: str,
    priority: str,
    reason: str,
    vuln_status: Optional[str],
    published: Optional[str],
    last_modified: Optional[str],
) -> Table:
    table = Table(title="SATEI Verdict", box=box.ROUNDED, show_lines=False)
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")

    table.add_row("CVE", cve_id)
    table.add_row("Prioridad", priority.upper())
    table.add_row("Motivo", reason)
    table.add_row("Estado", str(vuln_status or "-"))
    table.add_row("Publicado", str(published or "-"))
    table.add_row("Última modificación", str(last_modified or "-"))

    return table


def make_scoring_table(
    cvss: dict[str, Any],
    epss: Optional[dict[str, Any]],
    kev: Optional[dict[str, Any]],
) -> Table:
    table = Table(title="Risk Signals", box=box.ROUNDED, show_lines=False)
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")

    table.add_row("CVSS version", str(cvss.get("version") or "-"))
    table.add_row("CVSS base score", str(cvss.get("base_score") or "-"))
    table.add_row("CVSS severity", str(cvss.get("severity") or "-"))
    table.add_row("CVSS vector", str(cvss.get("vector") or "-"))

    if epss:
        table.add_row("EPSS", str(epss.get("epss", "-")))
        table.add_row("EPSS percentile", str(epss.get("percentile", "-")))
        table.add_row("EPSS date", str(epss.get("date", epss.get("created", "-"))))
    else:
        table.add_row("EPSS", "No data")

    table.add_row("In CISA KEV", "True" if kev else "False")

    if kev:
        table.add_row("KEV vendor", str(kev.get("vendorProject", "-")))
        table.add_row("KEV product", str(kev.get("product", "-")))
        table.add_row("KEV ransomware", str(kev.get("knownRansomwareCampaignUse", "-")))
        table.add_row("KEV date added", str(kev.get("dateAdded", "-")))
        table.add_row("KEV due date", str(kev.get("dueDate", "-")))

    return table


def make_description_panel(description: str) -> Panel:
    return Panel.fit(
        description,
        title="Description",
        border_style="cyan",
    )


@app.command()
def version() -> None:
    """Muestra la versión de SATEI."""
    console.print(f"[bold cyan]SATEI[/bold cyan] v{VERSION}")


@app.command()
def cve(
    value: str = typer.Argument(..., help="CVE a priorizar, por ejemplo CVE-2024-3400"),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Muestra la salida en formato JSON.",
    ),
) -> None:
    """Prioriza un CVE combinando NVD, EPSS y CISA KEV."""
    cve_id = validate_cve(value)

    if not json_output:
        console.print(
            Panel.fit(
                f"[bold white]SATEI[/bold white] → analizando [cyan]{cve_id}[/cyan]",
                border_style="cyan",
            )
        )

    try:
        nvd_cve = fetch_nvd_cve(cve_id)
    except requests.RequestException as exc:
        if json_output:
            typer.echo(
                json.dumps(
                    {
                        "tool": "SATEI",
                        "version": VERSION,
                        "query": {"type": "cve", "value": cve_id},
                        "error": f"Error consultando NVD: {exc}",
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
        else:
            console.print(f"[red]Error consultando NVD:[/red] {exc}")
        raise typer.Exit(code=1)
    except ValueError as exc:
        if json_output:
            typer.echo(
                json.dumps(
                    {
                        "tool": "SATEI",
                        "version": VERSION,
                        "query": {"type": "cve", "value": cve_id},
                        "error": str(exc),
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
        else:
            console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    try:
        epss_data = fetch_epss(cve_id)
    except requests.RequestException:
        epss_data = None

    try:
        kev_entry = fetch_kev_entry(cve_id)
    except requests.RequestException:
        kev_entry = None

    description = extract_description(nvd_cve)
    cvss = extract_cvss(nvd_cve)

    cvss_score = cvss.get("base_score")
    if cvss_score is not None:
        try:
            cvss_score = float(cvss_score)
        except (TypeError, ValueError):
            cvss_score = None

    epss_score = None
    if epss_data and epss_data.get("epss") is not None:
        try:
            epss_score = float(epss_data["epss"])
        except (TypeError, ValueError):
            epss_score = None

    priority, reason = calculate_priority(
        cvss_score=cvss_score,
        epss_score=epss_score,
        in_kev=bool(kev_entry),
    )

    payload = build_output_payload(
        cve_id=cve_id,
        priority=priority,
        reason=reason,
        nvd_cve=nvd_cve,
        description=description,
        cvss=cvss,
        epss_data=epss_data,
        kev_entry=kev_entry,
    )

    if json_output:
        typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    console.print()
    console.print(
        make_summary_table(
            cve_id=cve_id,
            priority=priority,
            reason=reason,
            vuln_status=nvd_cve.get("vulnStatus"),
            published=nvd_cve.get("published"),
            last_modified=nvd_cve.get("lastModified"),
        )
    )

    console.print()
    console.print(make_scoring_table(cvss=cvss, epss=epss_data, kev=kev_entry))

    console.print()
    console.print(make_description_panel(description))

if __name__ == "__main__":
    app()