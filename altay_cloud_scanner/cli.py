"""
CLI Komut Satırı Arayüzü
Click ile altay-cloud komutu
"""

import sys
import logging
from typing import Optional, List, Dict

import click

from .aws_session import AWSSessionManager
from .scanner import CloudScanner, MockScanner
from .ui import ConsoleUI
from .output import OutputManager
from .scoring import RiskScorer


# Log konfigürasyonu
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

# Botocore log seviyesini düşür
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """AltaySec Cloud Security Scanner
    
    AWS bulut ortamlarında güvenlik yapılandırma hatalarını tespit eden read-only tarayıcı.
    """
    pass


@cli.command()
@click.option(
    "--profile",
    "-p",
    default=None,
    help="AWS profile adı (varsayılan: default)",
)
@click.option(
    "--region",
    "-r",
    default="eu-north-1",
    help="Tarama bölgesi (varsayılan: eu-north-1)",
)
@click.option(
    "--regions",
    default=None,
    help="Bölge listesi (virgülle ayrılmış) veya 'all' için tüm bölgeler",
)
@click.option(
    "--expected-account",
    default=None,
    help="Beklenen AWS Account ID (12 haneli)",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["terminal", "json"], case_sensitive=False),
    default="terminal",
    help="Çıktı formatı (varsayılan: terminal)",
)
@click.option(
    "--out",
    default=None,
    help="Çıktı dosyası (json için)",
)
@click.option(
    "--mock",
    is_flag=True,
    help="Mock modu - AWS'e bağlanmadan demo tarama çalıştır",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Detaylı çıktı",
)
def scan(
    profile: Optional[str],
    region: str,
    regions: Optional[str],
    expected_account: Optional[str],
    output: str,
    out: Optional[str],
    mock: bool,
    verbose: bool,
):
    """AWS güvenlik taraması başlat"""
    
    ui = ConsoleUI(verbose=verbose)
    ui.print_header()
    
    region_list = _determine_regions(regions, region)
    
    if mock:
        return _run_mock_scan(ui, output, out, verbose, region_list)
    
    return _run_live_scan(
        ui, profile, region_list, expected_account, output, out, verbose
    )


def _determine_regions(regions_param: Optional[str], default_region: str) -> List[str]:
    """Taranacak bölgeleri belirle"""
    if regions_param:
        if regions_param.lower() == "all":
            return [
                "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
                "eu-north-1", "eu-south-1", "eu-south-2",
                "ap-southeast-1", "ap-southeast-2", "ap-south-1",
                "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
                "ca-central-1", "sa-east-1", "me-south-1",
                "af-south-1", "ap-east-1", "me-central-1",
            ]
        else:
            return [r.strip() for r in regions_param.split(",") if r.strip()]
    else:
        return [default_region]


def _run_mock_scan(
    ui: ConsoleUI,
    output: str,
    out: Optional[str],
    verbose: bool,
    region_list: List[str],
) -> None:
    """Mock tarama çalıştır"""
    ui.region = region_list
    ui.print_scan_start(region_list, mock=True)
    
    try:
        scanner = MockScanner(verbose=verbose)
        summary = scanner.scan()
        findings = scanner.get_findings()
        errors = scanner.get_errors()
        
        _display_results(ui, output, out, summary, findings, errors, account_id=None, mock=True)
        
    except Exception as e:
        ui.error(f"Mock tarama hatası: {e}")
        logger.exception("Mock scan error")
        sys.exit(1)


def _run_live_scan(
    ui: ConsoleUI,
    profile: Optional[str],
    region_list: List[str],
    expected_account: Optional[str],
    output: str,
    out: Optional[str],
    verbose: bool,
) -> None:
    """Live tarama çalıştır"""
    try:
        session_manager = AWSSessionManager(
            profile_name=profile,
            region=region_list[0],
            expected_account_id=expected_account,
        )
        
        caller_identity = session_manager.verify_caller_identity()
        account_id = caller_identity.get("Account")
        
        ui.region = region_list
        ui.print_scan_start(region_list, account_id=account_id, mock=False)
        
        scanner = CloudScanner(session_manager, region_list, verbose=verbose)
        summary = scanner.scan()
        findings = scanner.get_findings()
        errors = scanner.get_errors()
        
        _display_results(ui, output, out, summary, findings, errors, account_id, mock=False)
        
    except ValueError as e:
        ui.error(str(e))
        sys.exit(1)
    except Exception as e:
        ui.error(f"Tarama hatası: {e}")
        logger.exception("Live scan error")
        sys.exit(1)


def _display_results(
    ui: ConsoleUI,
    output: str,
    out: Optional[str],
    summary: Dict,
    findings: List[Dict],
    errors: List[Dict],
    account_id: Optional[str],
    mock: bool,
) -> None:
    """Sonuçları göster"""
    output_manager = OutputManager(output_format=output)
    
    regions = getattr(ui, 'region', [])
    output_manager.set_scan_info(
        account_id=account_id,
        regions=regions,
        mock=mock,
    )
    
    for finding in findings:
        output_manager.add_finding(finding)
    
    for error in errors:
        output_manager.add_error(error)
    
    output_manager.set_summary(summary)
    
    if output == "terminal":
        ui.print_scan_complete(summary)
        ui.print_findings_table(findings)
        if errors:
            ui.print_errors(errors)
    
    if output == "json":
        json_output = output_manager.get_json_string()
        click.echo(json_output)
        if out:
            output_manager.save_json(out)
            ui.success(f"JSON raporu kaydedildi: {out}")


def main():
    """Ana giriş noktası"""
    cli()


if __name__ == "__main__":
    main()