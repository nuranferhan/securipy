import socket
import struct
import threading
import time
import subprocess
import platform
import ipaddress
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
import re
from dataclasses import dataclass, asdict

@dataclass
class NetworkDevice:
    """Ağ cihazı bilgileri"""
    ip_address: str
    hostname: str = ""
    mac_address: str = ""
    os_fingerprint: str = ""
    open_ports: List[int] = None
    vendor: str = ""
    response_time: float = 0.0
    is_alive: bool = False
    services: Dict[int, str] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = {}

@dataclass
class NetworkSegment:
    """Ağ segmenti bilgileri"""
    network: str
    netmask: str
    gateway: str = ""
    dns_servers: List[str] = None
    devices: List[NetworkDevice] = None
    
    def __post_init__(self):
        if self.dns_servers is None:
            self.dns_servers = []
        if self.devices is None:
            self.devices = []

class NetworkAnalyzer:
    """
    Kapsamlı Ağ Analiz Aracı
    Ağ keşfi, cihaz tespiti, OS fingerprinting ve ağ topolojisi analizi
    """
    
    def __init__(self, timeout: float = 1.0, max_threads: int = 50):
        """
        Network Analyzer'ı başlatır
        
        Args:
            timeout: Ping ve bağlantı zaman aşımı
            max_threads: Maksimum thread sayısı
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.discovered_devices = []
        self.network_segments = []
        
        # OS detection patterns
        self.os_patterns = self.load_os_patterns()
        
        # MAC vendor veritabanı
        self.mac_vendors = self.load_mac_vendors()
    
    def load_os_patterns(self) -> Dict:
        """OS fingerprinting pattern'lerini yükler"""
        try:
            with open('data/os_patterns.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "windows": {
                    "ttl_values": [128, 64],
                    "window_size": [65535, 8192],
                    "patterns": ["Microsoft", "Windows", "IIS"]
                },
                "linux": {
                    "ttl_values": [64, 255],
                    "window_size": [5840, 5792],
                    "patterns": ["Linux", "Apache", "nginx"]
                },
                "macos": {
                    "ttl_values": [64],
                    "window_size": [65535],
                    "patterns": ["Darwin", "macOS"]
                }
            }
    
    def load_mac_vendors(self) -> Dict:
        """MAC vendor veritabanını yükler"""
        try:
            with open('data/mac_vendors.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "00:50:56": "VMware",
                "08:00:27": "VirtualBox",
                "00:0C:29": "VMware",
                "00:1B:21": "Intel",
                "00:23:24": "Apple",
                "B8:27:EB": "Raspberry Pi"
            }
    
    def discover_network(self, network_range: str, callback=None) -> List[NetworkDevice]:
        """
        Ağ keşfi yapar
        
        Args:
            network_range: CIDR formatında ağ aralığı (örn: 192.168.1.0/24)
            callback: İlerleme callback fonksiyonu
            
        Returns:
            List[NetworkDevice]: Keşfedilen cihazlar
        """
        devices = []
        
        try:
            # IP aralığını parse et
            network = ipaddress.IPv4Network(network_range, strict=False)
            ip_list = list(network.hosts())
            
            # Broadcast adresi de ekle
            if network.broadcast_address:
                ip_list.append(network.broadcast_address)
            
            print(f"Taranacak IP sayısı: {len(ip_list)}")
            completed = 0
            
            # Paralel ping taraması
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Ping işlemlerini başlat
                future_to_ip = {
                    executor.submit(self._ping_host, str(ip)): str(ip) 
                    for ip in ip_list
                }
                
                # Sonuçları topla
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    completed += 1
                    
                    try:
                        device_info = future.result()
                        if device_info and device_info.is_alive:
                            devices.append(device_info)
                            print(f"✓ Cihaz bulundu: {ip} - {device_info.hostname}")
                        
                        # İlerleme bildirimi
                        if callback:
                            progress = (completed / len(ip_list)) * 100
                            callback(progress, ip, device_info)
                            
                    except Exception as e:
                        print(f"Hata {ip}: {str(e)}")
            
            self.discovered_devices = devices
            
            # Bulunan cihazlar için detaylı analiz
            print(f"\n{len(devices)} cihaz bulundu. Detaylı analiz başlatılıyor...")
            self._analyze_discovered_devices(devices)
            
        except Exception as e:
            print(f"Ağ keşfi hatası: {str(e)}")
        
        return devices
    
    def _ping_host(self, ip: str) -> Optional[NetworkDevice]:
        """Tek bir host'a ping atar"""
        try:
            # Platform'a göre ping komutu
            if platform.system().lower() == "windows":
                ping_cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                ping_cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            start_time = time.time()
            result = subprocess.run(
                ping_cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.timeout + 1
            )
            response_time = (time.time() - start_time) * 1000  # ms
            
            if result.returncode == 0:
                device = NetworkDevice(
                    ip_address=ip,
                    is_alive=True,
                    response_time=response_time
                )
                
                # Hostname çözümlemesi
                try:
                    device.hostname = socket.gethostbyaddr(ip)[0]
                except:
                    device.hostname = ip
                
                return device
            
        except Exception:
            pass
        
        return None
    
    def _analyze_discovered_devices(self, devices: List[NetworkDevice]):
        """Keşfedilen cihazları detaylı analiz eder"""
        with ThreadPoolExecutor(max_workers=min(10, len(devices))) as executor:
            futures = {
                executor.submit(self._detailed_device_analysis, device): device 
                for device in devices
            }
            
            for future in as_completed(futures):
                device = futures[future]
                try:
                    updated_device = future.result()
                    if updated_device:
                        # Mevcut device'ı güncelle
                        device.mac_address = updated_device.mac_address
                        device.os_fingerprint = updated_device.os_fingerprint
                        device.open_ports = updated_device.open_ports
                        device.services = updated_device.services
                        device.vendor = updated_device.vendor
                except Exception as e:
                    print(f"Cihaz analiz hatası {device.ip_address}: {str(e)}")
    
    def _detailed_device_analysis(self, device: NetworkDevice) -> NetworkDevice:
        """Tek bir cihaz için detaylı analiz"""
        # MAC adresi öğrenme
        device.mac_address = self._get_mac_address(device.ip_address)
        if device.mac_address:
            device.vendor = self._get_vendor_from_mac(device.mac_address)
        
        # OS fingerprinting
        device.os_fingerprint = self._detect_os(device.ip_address)
        
        # Hızlı port taraması (yaygın portlar)
        device.open_ports, device.services = self._quick_port_scan(device.ip_address)
        
        return device
    
    def _get_mac_address(self, ip: str) -> str:
        """IP adresinin MAC adresini öğrenir"""
        try:
            if platform.system().lower() == "windows":
                # Windows ARP tablosu
                result = subprocess.run(
                    ["arp", "-a", ip], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            # MAC adresi pattern'i ara
                            mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                            if mac_match:
                                return mac_match.group().upper()
            else:
                # Linux/macOS ARP tablosu
                result = subprocess.run(
                    ["arp", "-n", ip], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                mac = parts[2]
                                if ':' in mac and len(mac) == 17:
                                    return mac.upper()
        except Exception:
            pass
        
        return ""
    
    def _get_vendor_from_mac(self, mac: str) -> str:
        """MAC adresinden vendor bilgisini çıkarır"""
        if not mac:
            return ""
        
        # İlk 3 oktet (OUI - Organizationally Unique Identifier)
        oui = mac[:8]  # XX:XX:XX formatı
        
        for oui_prefix, vendor in self.mac_vendors.items():
            if mac.startswith(oui_prefix.upper()):
                return vendor
        
        return "Unknown"
    
    def _detect_os(self, ip: str) -> str:
        """OS fingerprinting yapar"""
        try:
            # TCP SYN packet gönder ve TTL değerini kontrol et
            ttl = self._get_ttl(ip)
            
            # TTL değerine göre OS tahmini
            if ttl:
                if ttl <= 64:
                    if ttl == 64:
                        return "Linux/Unix"
                    else:
                        return "Linux/Unix (through router)"
                elif ttl <= 128:
                    if ttl == 128:
                        return "Windows"
                    else:
                        return "Windows (through router)"
                elif ttl <= 255:
                    return "Cisco/Network Device"
            
            # Banner-based detection
            banner_os = self._detect_os_from_banners(ip)
            if banner_os:
                return banner_os
                
        except Exception:
            pass
        
        return "Unknown"
    
    def _get_ttl(self, ip: str) -> Optional[int]:
        """TTL değerini ping ile öğrenir"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(
                    ["ping", "-n", "1", ip], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    # Windows ping output'undan TTL çıkar
                    ttl_match = re.search(r'TTL=(\d+)', result.stdout)
                    if ttl_match:
                        return int(ttl_match.group(1))
            else:
                result = subprocess.run(
                    ["ping", "-c", "1", ip], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    # Linux/macOS ping output'undan TTL çıkar
                    ttl_match = re.search(r'ttl=(\d+)', result.stdout)
                    if ttl_match:
                        return int(ttl_match.group(1))
        except Exception:
            pass
        
        return None
    
    def _detect_os_from_banners(self, ip: str) -> str:
        """Servis banner'larından OS tespiti"""
        common_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((ip, port)) == 0:
                    # Banner oku
                    try:
                        if port == 80 or port == 443:
                            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        sock.close()
                        
                        # Banner'dan OS çıkar
                        banner_lower = banner.lower()
                        if 'ubuntu' in banner_lower or 'debian' in banner_lower:
                            return "Linux (Ubuntu/Debian)"
                        elif 'centos' in banner_lower or 'redhat' in banner_lower:
                            return "Linux (CentOS/RedHat)"
                        elif 'microsoft' in banner_lower or 'windows' in banner_lower:
                            return "Windows Server"
                        elif 'apache' in banner_lower and 'unix' in banner_lower:
                            return "Unix/Linux"
                        elif 'iis' in banner_lower:
                            return "Windows (IIS)"
                        
                    except:
                        sock.close()
                else:
                    sock.close()
            except:
                continue
        
        return ""
    
    def _quick_port_scan(self, ip: str) -> Tuple[List[int], Dict[int, str]]:
        """Hızlı port taraması yapar"""
        open_ports = []
        services = {}
        
        # Yaygın portlar listesi
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1433: "SQL Server", 
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 8080: "HTTP-Alt"
        }
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {
                executor.submit(self._scan_single_port, ip, port): port 
                for port in common_ports.keys()
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open = future.result()
                    if is_open:
                        open_ports.append(port)
                        services[port] = common_ports[port]
                except Exception:
                    pass
        
        return sorted(open_ports), services
    
    def _scan_single_port(self, ip: str, port: int) -> bool:
        """Tek bir portu tarar"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def analyze_network_topology(self) -> Dict:
        """Ağ topolojisini analiz eder"""
        topology = {
            'segments': [],
            'gateways': [],
            'total_devices': len(self.discovered_devices),
            'device_types': {},
            'os_distribution': {},
            'vendor_distribution': {}
        }
        
        # Cihaz türleri analizi
        for device in self.discovered_devices:
            # Açık portlara göre cihaz türü tahmin et
            device_type = self._classify_device_type(device)
            if device_type in topology['device_types']:
                topology['device_types'][device_type] += 1
            else:
                topology['device_types'][device_type] = 1
            
            # OS dağılımı
            os = device.os_fingerprint or "Unknown"
            if os in topology['os_distribution']:
                topology['os_distribution'][os] += 1
            else:
                topology['os_distribution'][os] = 1
            
            # Vendor dağılımı
            vendor = device.vendor or "Unknown"
            if vendor in topology['vendor_distribution']:
                topology['vendor_distribution'][vendor] += 1
            else:
                topology['vendor_distribution'][vendor] = 1
        
        # Gateway tespiti
        topology['gateways'] = self._detect_gateways()
        
        return topology
    
    def _classify_device_type(self, device: NetworkDevice) -> str:
        """Cihaz türünü sınıflandırır"""
        open_ports = set(device.open_ports)
        
        # Web sunucusu
        if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
            if 22 in open_ports:  # SSH var
                return "Web Server (Linux)"
            elif 3389 in open_ports:  # RDP var
                return "Web Server (Windows)"
            else:
                return "Web Server"
        
        # Veritabanı sunucusu
        if 3306 in open_ports or 5432 in open_ports or 1433 in open_ports:
            return "Database Server"
        
        # Mail sunucusu
        if 25 in open_ports or 110 in open_ports or 143 in open_ports:
            return "Mail Server"
        
        # DNS sunucusu
        if 53 in open_ports:
            return "DNS Server"
        
        # Dosya paylaşım
        if 445 in open_ports or 139 in open_ports or 21 in open_ports:
            return "File Server"
        
        # Network cihazı
        if 23 in open_ports and len(open_ports) <= 3:
            return "Network Device"
        
        # Desktop/Workstation
        if 3389 in open_ports:  # RDP
            return "Windows Desktop"
        elif 22 in open_ports and len(open_ports) <= 2:
            return "Linux Desktop"
        
        # IoT/Embedded
        if len(open_ports) == 1 and (80 in open_ports or 443 in open_ports):
            return "IoT Device"
        
        return "Unknown Device"
    
    def _detect_gateways(self) -> List[str]:
        """Gateway cihazlarını tespit eder"""
        gateways = []
        
        try:
            if platform.system().lower() == "windows":
                # Windows route tablosu
                result = subprocess.run(
                    ["route", "print", "0.0.0.0"], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '0.0.0.0' in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                gateway = parts[2]
                                if gateway != '0.0.0.0' and gateway not in gateways:
                                    gateways.append(gateway)
            else:
                # Linux/macOS route tablosu
                result = subprocess.run(
                    ["route", "-n"], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.startswith('0.0.0.0') or 'default' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                gateway = parts[1]
                                if gateway not in gateways and '.' in gateway:
                                    gateways.append(gateway)
        except Exception:
            pass
        
        return gateways
    
    def get_network_interfaces(self) -> List[Dict]:
        """Yerel ağ arayüzlerini listeler"""
        interfaces = []
        
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(
                    ["ipconfig", "/all"], 
                    capture_output=True, 
                    text=True
                )
                # Windows ipconfig parsing
                interfaces = self._parse_windows_interfaces(result.stdout)
            else:
                result = subprocess.run(
                    ["ifconfig"], 
                    capture_output=True, 
                    text=True
                )
                # Linux/macOS ifconfig parsing
                interfaces = self._parse_unix_interfaces(result.stdout)
        except Exception as e:
            print(f"Interface listesi alınamadı: {str(e)}")
        
        return interfaces
    
    def _parse_windows_interfaces(self, output: str) -> List[Dict]:
        """Windows ipconfig çıktısını parse eder"""
        interfaces = []
        current_interface = {}
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            if 'adapter' in line.lower():
                if current_interface:
                    interfaces.append(current_interface)
                current_interface = {'name': line}
            
            elif 'IPv4 Address' in line:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    current_interface['ip'] = ip_match.group(1)
            
            elif 'Subnet Mask' in line:
                mask_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if mask_match:
                    current_interface['netmask'] = mask_match.group(1)
            
            elif 'Default Gateway' in line:
                gw_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if gw_match:
                    current_interface['gateway'] = gw_match.group(1)
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def _parse_unix_interfaces(self, output: str) -> List[Dict]:
        """Unix/Linux ifconfig çıktısını parse eder"""
        interfaces = []
        current_interface = {}
        
        lines = output.split('\n')
        for line in lines:
            if line and not line.startswith(' ') and not line.startswith('\t'):
                # Yeni interface başlangıcı
                if current_interface:
                    interfaces.append(current_interface)
                current_interface = {'name': line.split(':')[0]}
            
            elif 'inet ' in line:
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    current_interface['ip'] = ip_match.group(1)
                
                mask_match = re.search(r'netmask (\d+\.\d+\.\d+\.\d+)', line)
                if mask_match:
                    current_interface['netmask'] = mask_match.group(1)
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def export_network_analysis(self, filename: str, format: str = 'json'):
        """Ağ analizi sonuçlarını dosyaya aktarır"""
        os.makedirs('reports', exist_ok=True)
        filepath = os.path.join('reports', filename)
        
        analysis_data = {
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'discovered_devices': [asdict(device) for device in self.discovered_devices],
            'topology': self.analyze_network_topology(),
            'interfaces': self.get_network_interfaces()
        }
        
        if format.lower() == 'json':
            with open(f"{filepath}.json", 'w', encoding='utf-8') as f:
                json.dump(analysis_data, f, indent=2, ensure_ascii=False)
        
        elif format.lower() == 'html':
            html_content = self._generate_network_html_report(analysis_data)
            with open(f"{filepath}.html", 'w', encoding='utf-8') as f:
                f.write(html_content)
    
    def _generate_network_html_report(self, data: Dict) -> str:
        """HTML ağ analizi raporu oluşturur"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Ağ Analizi Raporu</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .device {{ border: 1px solid #ddd; margin: 10px; padding: 10px; }}
                .alive {{ background-color: #d4edda; }}
                .dead {{ background-color: #f8d7da; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .chart {{ margin: 20px 0; }}
            </style>
        </head>
        <body>
            <h1>Ağ Analizi Raporu</h1>
            <p><strong>Tarama Zamanı:</strong> {data['scan_time']}</p>
            <p><strong>Bulunan Cihaz Sayısı:</strong> {len(data['discovered_devices'])}</p>
            
            <h2>Bulunan Cihazlar</h2>
            <table>
                <tr>
                    <th>IP Adresi</th>
                    <th>Hostname</th>
                    <th>MAC Adresi</th>
                    <th>Vendor</th>
                    <th>OS</th>
                    <th>Açık Portlar</th>
                    <th>Yanıt Süresi</th>
                </tr>
        """
        
        for device in data['discovered_devices']:
            ports_str = ', '.join(map(str, device['open_ports'][:5]))  # İlk 5 port
            if len(device['open_ports']) > 5:
                ports_str += f" (+{len(device['open_ports'])-5} more)"
            
            html += f"""
                <tr>
                    <td>{device['ip_address']}</td>
                    <td>{device['hostname']}</td>
                    <td>{device['mac_address']}</td>
                    <td>{device['vendor']}</td>
                    <td>{device['os_fingerprint']}</td>
                    <td>{ports_str}</td>
                    <td>{device['response_time']:.1f}ms</td>
                </tr>
            """
        
        # Topoloji bilgileri
        topology = data['topology']
        html += f"""
            </table>
            
            <h2>Ağ Topolojisi</h2>
            <h3>Cihaz Türleri</h3>
            <ul>
        """
        
        for device_type, count in topology['device_types'].items():
            html += f"<li>{device_type}: {count}</li>"
        
        html += """
            </ul>
            
            <h3>İşletim Sistemi Dağılımı</h3>
            <ul>
        """
        
        for os, count in topology['os_distribution'].items():
            html += f"<li>{os}: {count}</li>"
        
        html += """
            </ul>
        </body>
        </html>
        """
        
        return html


# Test fonksiyonu
if __name__ == "__main__":
    def progress_callback(progress, ip, device):
        print(f"İlerleme: %{progress:.1f} - {ip}")
    
    analyzer = NetworkAnalyzer(timeout=1.0, max_threads=50)
    
    # Yerel ağ arayüzlerini listele
    print("Ağ arayüzleri:")
    interfaces = analyzer.get_network_interfaces()
    for interface in interfaces:
        print(f"- {interface}")
    
    # Ağ keşfi başlat
    print("\nAğ keşfi başlatılıyor...")
    devices = analyzer.discover_network("192.168.1.0/24", callback=progress_callback)
    
    if devices:
        print(f"\n{len(devices)} cihaz bulundu:")
        for device in devices:
            print(f"- {device.ip_address} ({device.hostname}) - {device.os_fingerprint}")
            if device.open_ports:
                print(f"  Açık portlar: {device.open_ports}")
        
        # Topoloji analizi
        topology = analyzer.analyze_network_topology()
        print(f"\nTopoloji Analizi:")
        print(f"Cihaz türleri: {topology['device_types']}")
        print(f"OS dağılımı: {topology['os_distribution']}")
        
        # Raporu kaydet
        analyzer.export_network_analysis('network_scan', 'json')
        print("\nRapor 'reports/network_scan.json' dosyasına kaydedildi.")
    else:
        print("Hiç cihaz bulunamadı.")