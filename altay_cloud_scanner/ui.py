"""
Terminal UI Çıktıları
Rich kütüphanesi ile modern, renkli çıktı formatları
"""

from typing import List, Dict, Optional
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.layout import Layout
from rich import box
from rich.text import Text
from rich.rule import Rule


class ConsoleUI:
    """Terminal UI yönetimi"""

    # Renk tanımları
    COLORS = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "green",
        "success": "green",
        "warning": "yellow",
        "error": "red",
        "header": "bold cyan",
        "score_a": "bold green",
        "score_b": "green",
        "score_c": "yellow",
        "score_d": "orange3",
        "score_f": "bold red",
    }

    def __init__(self, verbose: bool = False):
        self.console = Console()
        self.verbose = verbose
        self.start_time = None
        self.region = []

    def print_header(self) -> None:
        """Ana başlık panelini yazdır"""
        header_text = """
[cyan bold]AltaySec • Cloud Security Scanner[/cyan bold]
[white]Koray Yolcu • kkyolcu@gmail.com[/white]
"""
        panel = Panel(
            header_text,
            border_style="cyan",
            padding=(1, 2),
            box=box.DOUBLE,
        )
        self.console.print(panel)

    def print_scan_start(
        self,
        regions: List[str],
        account_id: Optional[str] = None,
        mock: bool = False
    ) -> None:
        """Tarama başlangıç bilgisini yazdır"""
        self.start_time = datetime.now()
        
        mode = "[yellow]MOCK MODE[/yellow]" if mock else "[green]LIVE SCAN[/green]"
        self.console.print(f"\nTarama Modu: {mode}")
        
        if account_id:
            self.console.print(f"AWS Account: [cyan]{account_id}[/cyan]")
        
        if len(regions) == 1:
            self.console.print(f"Bölge: [cyan]{regions[0]}[/cyan]")
        else:
            self.console.print(f"Bölgeler: [cyan]{len(regions)} bölge[/cyan]")
        
        self.console.print(Rule(style="dim"))

    def print_check_progress(self, check_name: str, status: str) -> None:
        """Check ilerlemesini yazdır (verbose modda)"""
        if self.verbose:
            status_symbol = {
                "running": "⏳",
                "success": "✓",
                "error": "✗",
                "skipped": "○",
            }.get(status, "•")
            
            color = {
                "running": "yellow",
                "success": "green",
                "error": "red",
                "skipped": "dim",
            }.get(status, "white")
            
            self.console.print(f"{status_symbol} [{color}]{check_name}[/{color}]")

    def print_scan_complete(self, summary: Dict) -> None:
        """Tarama tamamlandı özetini yazdır"""
        elapsed = datetime.now() - self.start_time if self.start_time else None
        elapsed_str = str(elapsed).split(".")[0] if elapsed else "Bilinmiyor"
        
        # Skor paneli
        score_color = self._get_score_color(summary["grade"])
        score_text = f"{summary['total_score']}/100"
        
        score_panel = Panel(
            f"[{score_color} bold]Güvenlik Skoru: {score_text} (Not: {summary['grade']})[/{score_color} bold]",
            border_style=score_color,
            padding=(1, 2),
        )
        self.console.print(score_panel)
        
        # Özet tablo
        table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
        table.add_column("Metrik", style="white")
        table.add_column("Değer", justify="right")
        
        table.add_row("Toplam Bulgu", f"{summary['total_findings']}")
        table.add_row("Kritik/HIGH", f"[red]{summary['severity_counts']['critical']}/{summary['severity_counts']['high']}[/red]")
        table.add_row("MEDIUM/LOW", f"[yellow]{summary['severity_counts']['medium']}/{summary['severity_counts']['low']}[/yellow]")
        table.add_row("Tarama Hataları", f"[red]{summary['total_errors']}[/red]")
        table.add_row("Süre", elapsed_str)
        
        self.console.print(table)
        
        # Kısmi tarama uyarısı
        if summary["is_partial_scan"]:
            self.console.print(
                "\n[yellow]⚠ Kısmi tarama: Bazı check'ler erişim hatası nedeniyle çalıştırılamadı.[/yellow]"
            )

    def print_findings_table(self, findings: List[Dict], limit: int = 50) -> None:
        """Bulguları tablo formatında yazdır"""
        if not findings:
            self.console.print("\n[green]✓ Güvenlik bulgusu bulunamadı![/green]")
            return
        
        findings_sorted = sorted(
            findings,
            key=lambda x: self._severity_rank(x.get("severity", "low")),
            reverse=True
        )
        
        display_findings = findings_sorted[:limit]
        
        table = Table(
            show_header=True,
            header_style="bold cyan",
            box=box.ROUNDED,
            title=f"\n[bold]Bulgular (Toplam: {len(findings)})[/bold]",
        )
        table.add_column("ID", style="dim", width=18)
        table.add_column("Hizmet", style="cyan", width=8)
        table.add_column("Severity", width=10)
        table.add_column("Kaynak", style="yellow", width=25)
        table.add_column("Risk", width=35)
        
        for finding in display_findings:
            severity = finding.get("severity", "info")
            color = self.COLORS.get(severity, "white")
            
            # Kaynak adı kısalt
            resource = finding.get("resource", {})
            resource_name = resource.get("name", resource.get("arn", "Bilinmiyor"))
            if len(resource_name) > 23:
                resource_name = resource_name[:20] + "..."
            
            table.add_row(
                finding.get("id", "N/A"),
                finding.get("service", "unknown"),
                f"[{color}]{severity.upper()}[/{color}]",
                resource_name,
                finding.get("risk", "")[:33],
            )
        
        self.console.print(table)
        
        if len(findings) > limit:
            self.console.print(
                f"\n[dim]... ve {len(findings) - limit} bulgu daha (JSON çıktısı için --output json kullanın)[/dim]"
            )

    def print_finding_detail(self, finding: Dict) -> None:
        """Tek bulgu detayını yazdır"""
        severity = finding.get("severity", "info")
        color = self.COLORS.get(severity, "white")
        
        panel_content = f"""
[bold cyan]ID:[/bold cyan] {finding.get('id', 'N/A')}
[bold cyan]Severity:[/bold cyan] [{color}]{severity.upper()}[/{color}]
[bold cyan]Hizmet:[/bold cyan] {finding.get('service', 'unknown')}
[bold cyan]Kaynak:[/bold cyan] {finding.get('resource', {}).get('arn', 'N/A')}

[bold yellow]Risk:[/bold yellow]
{finding.get('risk', 'Açıklama yok')}

[bold cyan]Deliller:[/bold cyan]
"""
        for evidence in finding.get("evidence", []):
            panel_content += f"• {evidence}\n"
        
        panel_content += "\n[bold green]Öneriler:[/bold green]\n"
        for rec in finding.get("recommendation", []):
            panel_content += f"• {rec}\n"
        
        panel = Panel(
            panel_content,
            title=finding.get("title", "Bulgu Detayı"),
            border_style=color,
            box=box.ROUNDED,
        )
        self.console.print(panel)

    def print_errors(self, errors: List[Dict]) -> None:
        """Hata listesini yazdır"""
        if not errors:
            return
        
        table = Table(
            show_header=True,
            header_style="bold red",
            box=box.SIMPLE,
            title="[bold red]Tarama Hataları[/bold red]",
        )
        table.add_column("Check", style="white")
        table.add_column("Hata", style="red")
        
        for error in errors:
            table.add_row(
                error.get("check", "Bilinmiyor"),
                error.get("error", "Bilinmeyen hata"),
            )
        
        self.console.print(table)

    def create_progress_bar(self, tasks: List[str]) -> Progress:
        """İlerleme çubuğu oluştur"""
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console,
        )
        
        return progress

    def _severity_rank(self, severity: str) -> int:
        """Severity sıralama değeri"""
        ranks = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        return ranks.get(severity.lower(), 0)

    def _get_score_color(self, grade: str) -> str:
        """Skor grade için renk döndür"""
        return self.COLORS.get(f"score_{grade.lower()}", "white")

    def error(self, message: str) -> None:
        """Hata mesajı yazdır"""
        self.console.print(f"[red]✗ HATA: {message}[/red]")

    def warning(self, message: str) -> None:
        """Uyarı mesajı yazdır"""
        self.console.print(f"[yellow]⚠ UYARI: {message}[/yellow]")

    def success(self, message: str) -> None:
        """Başarı mesajı yazdır"""
        self.console.print(f"[green]✓ {message}[/green]")

    def info(self, message: str) -> None:
        """Bilgi mesajı yazdır"""
        self.console.print(f"[dim]ℹ {message}[/dim]")