import argparse
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

from .port_scanner import PortScanner
from .vulnerability_scanner import VulnerabilityScanner
from .network_analyzer import NetworkAnalyzer
from .utils import (
    IPUtils, PortUtils, NetworkUtils, TimeUtils, 
    LoggingUtils, ConfigUtils, ValidationUtils
)

class SecuriPyCLI:
    
    def __init__(self):
        self.port_scanner = PortScanner()
        self.vuln_scanner = VulnerabilityScanner()
        self.network_analyzer = NetworkAnalyzer()
        
        self.config = ConfigUtils.load_config()
        self.verbose = False
    
    def create_parser(self) -> argparse.ArgumentParser:
    
        parser = argparse.ArgumentParser(
            prog='securipy',
            description='🛡️ SecuriPy - Kapsamlı Güvenlik Aracı Seti',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Örnekler:
  securipy scan -t 192.168.1.1 -p 1-1000           # Port taraması
  securipy vuln -t example.com                     # Güvenlik açığı taraması  
  securipy network -r 192.168.1.0/24               # Ağ analizi
  securipy scan -t 192.168.1.1 --tcp --udp         # TCP ve UDP tarama
  securipy vuln -t target.com --severity high      # Yüksek riskli zafiyetler
  
Güvenlik Uyarısı:
  Bu araç sadece yasal ve etik amaçlarla kullanılmalıdır.
  Sadece sahip olduğunuz veya izin aldığınız sistemlerde test yapın.
            """
        )
        
        parser.add_argument('-v', '--verbose', action='store_true',
                           help='Detaylı çıktı göster')
        parser.add_argument('--config', type=str,
                           help='Özel konfigürasyon dosyası')
        parser.add_argument('--output', '-o', type=str,
                           help='Çıktı dosyası adı')
        parser.add_argument('--format', choices=['json', 'txt', 'html'],
                           default='json', help='Çıktı formatı')
        
        subparsers = parser.add_subparsers(dest='command', help='Mevcut komutlar')
        
        self._add_scan_parser(subparsers)
        
        self._add_vuln_parser(subparsers)
        
        self._add_network_parser(subparsers)
        
        self._add_utility_parsers(subparsers)
        
        return parser
    
    def _add_scan_parser(self, subparsers):
        scan_parser = subparsers.add_parser('scan', help='Port taraması yap')
        
        scan_parser.add_argument('-t', '--target', required=True,
                                help='Hedef IP adresi veya domain')
        
        port_group = scan_parser.add_mutually_exclusive_group()
        port_group.add_argument('-p', '--ports', default='1-1000',
                               help='Port aralığı (örn: 1-1000, 80,443)')
        port_group.add_argument('--common', action='store_true',
                               help='Yaygın portları tara')
        port_group.add_argument('--all', action='store_true',
                               help='Tüm portları tara (1-65535)')
        
        scan_parser.add_argument('--tcp', action='store_true', default=True,
                                help='TCP taraması (varsayılan)')
        scan_parser.add_argument('--udp', action='store_true',
                                help='UDP taraması')
        
        scan_parser.add_argument('--threads', type=int, default=50,
                                help='Thread sayısı (varsayılan: 50)')
        scan_parser.add_argument('--timeout', type=float, default=1.0,
                                help='Timeout süresi (varsayılan: 1.0)')
        
        scan_parser.add_argument('--no-banner', action='store_true',
                                help='Banner grabbing yapma')
        scan_parser.add_argument('--service-detection', action='store_true',
                                help='Servis tespiti yap')
    
    def _add_vuln_parser(self, subparsers):
        vuln_parser = subparsers.add_parser('vuln', help='Güvenlik açığı taraması')
        
        vuln_parser.add_argument('-t', '--target', required=True,
                                help='Hedef IP adresi veya domain')
        
        vuln_parser.add_argument('--web', action='store_true', default=True,
                                help='Web uygulama güvenlik açıkları')
        vuln_parser.add_argument('--service', action='store_true',
                                help='Servis güvenlik açıkları')
        vuln_parser.add_argument('--config', action='store_true',
                                help='Konfigürasyon kontrolleri')
        
        vuln_parser.add_argument('--severity', 
                                choices=['low', 'medium', 'high', 'critical'],
                                default='low', help='Minimum şiddet seviyesi')
        vuln_parser.add_argument('--cve-only', action='store_true',
                                help='Sadece CVE\'li zafiyetleri göster')
        
        vuln_parser.add_argument('--ports', 
                                help='Belirli portları kontrol et')
    
    def _add_network_parser(self, subparsers):
       
        network_parser = subparsers.add_parser('network', help='Ağ analizi yap')
        
        network_parser.add_argument('-r', '--range', required=True,
                                   help='Ağ aralığı (CIDR formatında)')
        
        network_parser.add_argument('--ping-only', action='store_true',
                                   help='Sadece ping sweep yap')
        network_parser.add_argument('--os-detection', action='store_true',
                                   help='OS tespiti yap')
        network_parser.add_argument('--port-discovery', action='store_true',
                                   help='Port keşfi yap')
        
        network_parser.add_argument('--ping-timeout', type=float, default=1.0,
                                   help='Ping timeout (varsayılan: 1.0)')
        network_parser.add_argument('--max-hosts', type=int,
                                   help='Maksimum taranacak host sayısı')
    
    def _add_utility_parsers(self, subparsers):
        
        
        info_parser = subparsers.add_parser('info', help='Sistem ve hedef bilgileri')
        info_parser.add_argument('target', nargs='?', help='Hedef IP/domain')
        
        config_parser = subparsers.add_parser('config', help='Konfigürasyon yönetimi')
        config_subparsers = config_parser.add_subparsers(dest='config_action')
        
        config_subparsers.add_parser('show', help='Mevcut konfigürasyonu göster')
        
        config_set = config_subparsers.add_parser('set', help='Konfigürasyon ayarla')
        config_set.add_argument('key', help='Ayar anahtarı (örn: scan_settings.timeout)')
        config_set.add_argument('value', help='Ayar değeri')
        
        subparsers.add_parser('version', help='Versiyon bilgisi göster')
    
    def run(self, args=None):
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)
        
        self.verbose = parsed_args.verbose
        
        if not parsed_args.command:
            parser.print_help()
            return 1
        
        try:
            if parsed_args.command == 'scan':
                return self._handle_scan(parsed_args)
            elif parsed_args.command == 'vuln':
                return self._handle_vuln(parsed_args)
            elif parsed_args.command == 'network':
                return self._handle_network(parsed_args)
            elif parsed_args.command == 'info':
                return self._handle_info(parsed_args)
            elif parsed_args.command == 'config':
                return self._handle_config(parsed_args)
            elif parsed_args.command == 'version':
                return self._handle_version(parsed_args)
            else:
                parser.print_help()
                return 1
                
        except KeyboardInterrupt:
            self._print_error("\n⚠️ İşlem kullanıcı tarafından durduruldu")
            return 130
        except Exception as e:
            self._print_error(f"❌ Hata: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return 1
    
    def _handle_scan(self, args) -> int:
        target = args.target
        
        if not (IPUtils.is_valid_ip(target) or ValidationUtils.is_valid_domain(target)):
            self._print_error(f"❌ Geçersiz hedef: {target}")
            return 1
        
        self._print_info(f"🔍 Port taraması başlatılıyor: {target}")
        
        if args.all:
            start_port, end_port = 1, 65535
        elif args.common:
            common_ports = PortUtils.get_common_ports()
            start_port, end_port = min(common_ports), max(common_ports)
        else:
            try:
                if ',' in args.ports:
                    ports = [int(p.strip()) for p in args.ports.split(',')]
                    start_port, end_port = min(ports), max(ports)
                else:
                    start_port, end_port = PortUtils.parse_port_range(args.ports)
            except:
                self._print_error(f"❌ Geçersiz port aralığı: {args.ports}")
                return 1
        
        self.port_scanner.timeout = args.timeout
        self.port_scanner.max_threads = args.threads
        
        def progress_callback(progress, port, result):
            if self.verbose and result.get('state') == 'open':
                service = result.get('service', 'unknown')
                self._print_success(f"  ✓ Port {port} açık ({service})")
        
        start_time = time.time()
        
        protocol = 'tcp'
        if args.udp:
            protocol = 'udp'
        
        results = self.port_scanner.scan_range(
            target, start_port, end_port, protocol, progress_callback
        )
        
        duration = time.time() - start_time
        
        self._display_scan_results(results, duration)
        
        if args.output:
            self._save_report(results, args.output, args.format)
        
        return 0
    
    def _handle_vuln(self, args) -> int:
        target = args.target
        
        self._print_info(f"🔒 Güvenlik açığı taraması başlatılıyor: {target}")
        
        vulnerabilities = []
        
        if args.web:
            self._print_info("  📱 Web uygulama güvenlik açıkları kontrol ediliyor...")
            web_vulns = self.vuln_scanner._scan_web_vulnerabilities(target, 80)
            vulnerabilities.extend(web_vulns)
        
        if args.service:
            self._print_info("  🔧 Servis güvenlik açıkları kontrol ediliyor...")
          
            common_ports = PortUtils.get_common_ports()
            for port in common_ports:
                if NetworkUtils.is_port_open(target, port, 2.0):
                    service = PortUtils.get_service_name(port)
                    service_vulns = self.vuln_scanner.scan_service_vulnerabilities(
                        target, port, service, ""
                    )
                    vulnerabilities.extend(service_vulns)
        
        severity_levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        min_severity = severity_levels.get(args.severity, 0)
        
        filtered_vulns = []
        for vuln in vulnerabilities:
            vuln_severity = severity_levels.get(vuln.severity.value.lower(), 0)
            if vuln_severity >= min_severity:
                filtered_vulns.append(vuln)
        
        self._display_vuln_results(filtered_vulns)
        
        if args.output:
            report = self.vuln_scanner.generate_vulnerability_report(filtered_vulns)
            self._save_report(report, args.output, args.format)
        
        return 0
    
    def _handle_network(self, args) -> int:
        network_range = args.range
        
        if not IPUtils.is_valid_cidr(network_range):
            self._print_error(f"❌ Geçersiz CIDR formatı: {network_range}")
            return 1
        
        self._print_info(f"🌐 Ağ analizi başlatılıyor: {network_range}")
        
        self.network_analyzer.timeout = args.ping_timeout
        
        def progress_callback(progress, ip, device):
            if self.verbose and device and device.is_alive:
                self._print_success(f"  ✓ Cihaz bulundu: {ip} ({device.hostname})")
        
        devices = self.network_analyzer.discover_network(network_range, progress_callback)
        
        topology = self.network_analyzer.analyze_network_topology()
        
        self._display_network_results(devices, topology)
        
        if args.output:
            report_data = {
                'devices': [vars(d) for d in devices],
                'topology': topology
            }
            self._save_report(report_data, args.output, args.format)
        
        return 0
    
    def _handle_info(self, args) -> int:
        if args.target:
            target = args.target
            self._print_info(f"ℹ️ Hedef bilgileri: {target}")
            
            if IPUtils.is_valid_ip(target):
                ip = target
                hostname = NetworkUtils.resolve_hostname(ip)
            else:
                hostname = target
                ip = NetworkUtils.resolve_ip(hostname)
            
            print(f"  IP Adresi: {ip}")
            print(f"  Hostname: {hostname}")
            print(f"  Private IP: {'Evet' if IPUtils.is_private_ip(ip) else 'Hayır'}")
            
            is_alive, response_time = NetworkUtils.ping_host(ip)
            print(f"  Ping: {'✓ Yanıt veriyor' if is_alive else '✗ Yanıt vermiyor'}")
            if is_alive:
                print(f"  Yanıt Süresi: {response_time:.1f} ms")
        
        else:
            self._print_info("ℹ️ Sistem bilgileri:")
            
            import platform
            print(f"  Platform: {platform.system()} {platform.release()}")
            print(f"  Python: {platform.python_version()}")
            print(f"  Yerel IP: {NetworkUtils.get_local_ip()}")
            
            interfaces = self.network_analyzer.get_network_interfaces()
            if interfaces:
                print(f"  Ağ Arayüzleri:")
                for iface in interfaces[:3]:  # İlk 3'ü göster
                    print(f"    - {iface.get('name', 'Unknown')}: {iface.get('ip', 'N/A')}")
        
        return 0
    
    def _handle_config(self, args) -> int:
        if args.config_action == 'show':
            self._print_info("⚙️ Mevcut konfigürasyon:")
            config = ConfigUtils.load_config()
            print(json.dumps(config, indent=2, ensure_ascii=False))
        
        elif args.config_action == 'set':
            self._print_info(f"⚙️ Ayar güncelleniyor: {args.key} = {args.value}")
            
            value = args.value
            if value.lower() in ['true', 'false']:
                value = value.lower() == 'true'
            elif value.isdigit():
                value = int(value)
            elif '.' in value and value.replace('.', '').isdigit():
                value = float(value)
            
            ConfigUtils.set_setting(args.key, value)
            self._print_success(f"✓ Ayar kaydedildi: {args.key} = {value}")
        
        else:
            self._print_info("⚙️ Konfigürasyon yönetimi")
            print("Kullanım:")
            print("  securipy config show          # Mevcut ayarları göster")
            print("  securipy config set KEY VALUE # Ayar değiştir")
        
        return 0
    
    def _handle_version(self, args) -> int:
        print("🛡️ SecuriPy - Kapsamlı Güvenlik Aracı Seti")
        print("Versiyon: 1.0.0")
        print("Python: " + sys.version.split()[0])
        print("Platform: " + sys.platform)
        print("\nGeliştirici: SecuriPy Development Team")
        print("Lisans: MIT")
        print("GitHub: https://github.com/username/SecuriPy")
        return 0
    
    def _display_scan_results(self, results: Dict, duration: float):
        
        stats = results.get('statistics', {})
        open_ports = results.get('open_ports', [])
        
        print(f"\n📊 Tarama Özeti:")
        print(f"  Hedef: {results.get('host', 'N/A')}")
        print(f"  Süre: {duration:.2f} saniye")
        print(f"  Toplam Port: {stats.get('total_ports', 0)}")
        print(f"  Açık Port: {len(open_ports)}")
        print(f"  Kapalı Port: {stats.get('closed_ports', 0)}")
        print(f"  Filtrelenmiş: {stats.get('filtered_ports', 0)}")
        
        if open_ports:
            print(f"\n🔓 Açık Portlar:")
            for port in sorted(open_ports):
                port_info = results['ports'][port]
                service = port_info.get('service', 'unknown')
                banner = port_info.get('banner', '')[:50]
                
                port_line = f"  {port:>5} - {service:<12}"
                if banner:
                    port_line += f" | {banner}"
                
                print(port_line)
    
    def _display_vuln_results(self, vulnerabilities: List):
        
        if not vulnerabilities:
            self._print_success("✅ Güvenlik açığı bulunamadı!")
            return
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        print(f"\n🔒 Güvenlik Açıkları Özeti:")
        print(f"  Toplam: {len(vulnerabilities)}")
        for severity, count in severity_counts.items():
            if count > 0:
                emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
                print(f"  {emoji.get(severity, '⚪')} {severity}: {count}")
        
        print(f"\n📋 Bulunan Güvenlik Açıkları:")
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_emoji = {
                'Critical': '🔴', 'High': '🟠', 
                'Medium': '🟡', 'Low': '🟢'
            }
            
            print(f"\n  {i}. {severity_emoji.get(vuln.severity.value, '⚪')} {vuln.title}")
            print(f"     CVE: {vuln.cve_id}")
            print(f"     Severity: {vuln.severity.value} (CVSS: {vuln.cvss_score})")
            print(f"     Servis: {vuln.affected_service}")
            print(f"     Açıklama: {vuln.description[:100]}...")
            
            if self.verbose:
                print(f"     Çözüm: {vuln.solution}")
                if vuln.references:
                    print(f"     Referanslar: {', '.join(vuln.references[:2])}")
    
    def _display_network_results(self, devices: List, topology: Dict):
        
        print(f"\n🌐 Ağ Analizi Özeti:")
        print(f"  Bulunan Cihaz: {len(devices)}")
        
        device_types = topology.get('device_types', {})
        if device_types:
            print(f"  Cihaz Türleri:")
            for device_type, count in device_types.items():
                print(f"    - {device_type}: {count}")
        
        os_dist = topology.get('os_distribution', {})
        if os_dist:
            print(f"  İşletim Sistemleri:")
            for os_name, count in list(os_dist.items())[:5]:  
                print(f"    - {os_name}: {count}")
        
        if devices:
            print(f"\n💻 Bulunan Cihazlar:")
            for device in devices:
                ip = device.ip_address
                hostname = device.hostname if device.hostname != ip else "N/A"
                os_info = device.os_fingerprint or "Unknown"
                
                device_line = f"  {ip:<15} | {hostname:<20} | {os_info}"
                
                if device.open_ports:
                    ports_str = ', '.join(map(str, device.open_ports[:3]))
                    if len(device.open_ports) > 3:
                        ports_str += f" (+{len(device.open_ports)-3})"
                    device_line += f" | Portlar: {ports_str}"
                
                print(device_line)
    
    def _save_report(self, data: Dict, filename: str, format: str):
    
        timestamp = TimeUtils.get_timestamp()
        full_filename = f"{filename}_{timestamp}"
        
        try:
            if format == 'json':
                import json
                filepath = f"reports/{full_filename}.json"
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            
            elif format == 'txt':
                filepath = f"reports/{full_filename}.txt"
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(f"SecuriPy Raporu\n")
                    f.write(f"Oluşturma Tarihi: {TimeUtils.get_readable_time()}\n")
                    f.write("="*50 + "\n\n")
                    f.write(str(data))
            
            elif format == 'html':
                filepath = f"reports/{full_filename}.html"
                html_content = self._generate_html_report(data)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            
            self._print_success(f"📄 Rapor kaydedildi: {filepath}")
            
        except Exception as e:
            self._print_error(f"❌ Rapor kaydetme hatası: {e}")
    
    def _generate_html_report(self, data: Dict) -> str:
       
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecuriPy CLI Raporu</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                pre {{ background: #f8f9fa; padding: 10px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ SecuriPy CLI Raporu</h1>
                <p>Oluşturulma Tarihi: {TimeUtils.get_readable_time()}</p>
            </div>
            <div class="section">
                <h2>📊 Rapor Verileri</h2>
                <pre>{json.dumps(data, indent=2, ensure_ascii=False, default=str)}</pre>
            </div>
        </body>
        </html>
        """
        return html
    
    def _print_info(self, message: str):
        print(f"ℹ️  {message}")
        if self.config.get('security_settings', {}).get('log_scans', False):
            LoggingUtils.log_to_file(f"INFO: {message}")
    
    def _print_success(self, message: str):
        print(f"✅ {message}")
    
    def _print_error(self, message: str):
        print(f"❌ {message}", file=sys.stderr)
        LoggingUtils.log_error(message)
    
    def _print_warning(self, message: str):
        print(f"⚠️  {message}")


def main():
    cli = SecuriPyCLI()
    
    print("🛡️ SecuriPy - Kapsamlı Güvenlik Aracı Seti")
    print("=" * 50)
    
    try:
        return cli.run()
    except KeyboardInterrupt:
        print("\n⚠️ İşlem kullanıcı tarafından durduruldu")
        return 130
    except Exception as e:
        print(f"❌ Beklenmeyen hata: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())