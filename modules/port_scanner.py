import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from typing import List, Dict, Tuple, Optional
import subprocess
import re

class PortScanner:
   
    
    def __init__(self, timeout: float = 1.0, max_threads: int = 100):
   
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.services = {}
        self.banners = {}
        self.scan_results = {}
        
        self.load_common_ports()
        self.load_service_banners()
    
    def load_common_ports(self):
        try:
            with open('data/common_ports.json', 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    self.common_ports = self.get_default_common_ports()
                    print("Uyarı: common_ports.json dosyası boş, varsayılan portlar kullanılıyor.")
                    return
                
                f.seek(0)
                self.common_ports = json.load(f)
                
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Uyarı: common_ports.json yüklenemedi ({e}), varsayılan portlar kullanılıyor.")
            self.common_ports = self.get_default_common_ports()
        except Exception as e:
            print(f"Beklenmeyen hata: {e}, varsayılan portlar kullanılıyor.")
            self.common_ports = self.get_default_common_ports()
    
    def load_service_banners(self):
        try:
            with open('data/banners.json', 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    self.service_banners = self.get_default_banners()
                    print("Uyarı: banners.json dosyası boş, varsayılan banner'lar kullanılıyor.")
                    return
                
                f.seek(0)
                self.service_banners = json.load(f)
                
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Uyarı: banners.json yüklenemedi ({e}), varsayılan banner'lar kullanılıyor.")
            self.service_banners = self.get_default_banners()
        except Exception as e:
            print(f"Beklenmeyen hata: {e}, varsayılan banner'lar kullanılıyor.")
            self.service_banners = self.get_default_banners()
    
    def get_default_common_ports(self):
        return {
            "21": "FTP",
            "22": "SSH", 
            "23": "Telnet", 
            "25": "SMTP",
            "53": "DNS", 
            "80": "HTTP", 
            "110": "POP3", 
            "143": "IMAP",
            "443": "HTTPS", 
            "465": "SMTPS",
            "587": "SMTP (submission)",
            "993": "IMAPS", 
            "995": "POP3S",
            "3389": "RDP", 
            "5432": "PostgreSQL", 
            "3306": "MySQL",
            "1433": "MSSQL",
            "5900": "VNC",
            "8080": "HTTP-Proxy"
        }
    
    def get_default_banners(self):
        return {
            "21": ["220 FTP Server ready", "220 ProFTPD", "220 vsftpd"],
            "22": ["SSH-2.0-OpenSSH", "SSH-1.99-Cisco", "SSH-2.0-libssh"],
            "23": ["Login:", "Telnet Server Ready"],
            "25": ["220 SMTP Server ready", "220 Postfix", "220 Sendmail"],
            "53": ["DNS Server"],
            "80": ["Server: Apache", "Server: nginx", "Server: IIS"],
            "110": ["POP3 Server ready", "+OK POP3"],
            "143": ["* OK IMAP4", "IMAP4 Server ready"],
            "443": ["Server: Apache", "Server: nginx", "Server: IIS"],
            "993": ["* OK IMAPS ready"],
            "995": ["+OK POP3S ready"]
        }
    
    def scan_port(self, host: str, port: int, protocol: str = 'tcp') -> Dict:
 
        result = {
            'port': port,
            'protocol': protocol,
            'state': 'closed',
            'service': 'unknown',
            'banner': '',
            'version': ''
        }
        
        try:
            if protocol.lower() == 'tcp':
                result = self._scan_tcp_port(host, port, result)
            elif protocol.lower() == 'udp':
                result = self._scan_udp_port(host, port, result)
                
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _scan_tcp_port(self, host: str, port: int, result: Dict) -> Dict:
      
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            connection_result = sock.connect_ex((host, port))
            
            if connection_result == 0:
                result['state'] = 'open'
                result['service'] = self.common_ports.get(str(port), 'unknown')
                
                banner = self._grab_banner(sock, port)
                if banner:
                    result['banner'] = banner
                    result['version'] = self._extract_version(banner, port)
                    
        except socket.timeout:
            result['state'] = 'filtered'
        except Exception as e:
            result['state'] = 'filtered'
            result['error'] = str(e)
        finally:
            sock.close()
            
        return result
    
    def _scan_udp_port(self, host: str, port: int, result: Dict) -> Dict:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            test_message = b"SecuriPy UDP Scan"
            sock.sendto(test_message, (host, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                result['state'] = 'open'
                result['service'] = self.common_ports.get(str(port), 'unknown')
                if data:
                    result['banner'] = data.decode('utf-8', errors='ignore')[:100]
            except socket.timeout:
                result['state'] = 'open|filtered'
                
        except Exception as e:
            result['state'] = 'closed'
            result['error'] = str(e)
        finally:
            sock.close()
            
        return result
    
    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        try:
            if port == 80: 
                sock.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
            elif port == 443: 
                return ""  
            elif port == 21:  
                pass  
            elif port == 22:  
                pass  
            elif port == 25: 
                pass  
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return banner.strip()[:200]  
            
        except:
            return ""
    
    def _extract_version(self, banner: str, port: int) -> str:
        """Banner'dan versiyon bilgisini çıkarır"""
        version_patterns = [
            r'(\d+\.\d+(?:\.\d+)?)', 
            r'Apache/(\d+\.\d+\.\d+)',  
            r'nginx/(\d+\.\d+\.\d+)',   
            r'OpenSSH_(\d+\.\d+)',     
            r'Microsoft-IIS/(\d+\.\d+)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    def scan_range(self, host: str, start_port: int, end_port: int, 
                   protocol: str = 'tcp', callback=None) -> Dict:
 
        results = {
            'host': host,
            'protocol': protocol,
            'start_time': time.time(),
            'ports': {},
            'open_ports': [],
            'statistics': {}
        }
        
        ports_to_scan = list(range(start_port, end_port + 1))
        completed_ports = 0
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            
            future_to_port = {
                executor.submit(self.scan_port, host, port, protocol): port 
                for port in ports_to_scan
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    results['ports'][port] = result
                    
                    if result['state'] == 'open':
                        results['open_ports'].append(port)
                    
                    completed_ports += 1
                    
                    if callback:
                        progress = (completed_ports / len(ports_to_scan)) * 100
                        callback(progress, port, result)
                        
                except Exception as e:
                    results['ports'][port] = {
                        'port': port,
                        'state': 'error',
                        'error': str(e)
                    }
        
        results['end_time'] = time.time()
        results['duration'] = results['end_time'] - results['start_time']
        results['statistics'] = self._calculate_statistics(results)
        
        return results
    
    def scan_common_ports(self, host: str, protocol: str = 'tcp', callback=None) -> Dict:
  
        common_port_numbers = [int(port) for port in self.common_ports.keys()]
        return self.scan_range(host, min(common_port_numbers), 
                             max(common_port_numbers), protocol, callback)
    
    def aggressive_scan(self, host: str, callback=None) -> Dict:
  
        return self.scan_range(host, 1, 65535, 'tcp', callback)
    
    def _calculate_statistics(self, results: Dict) -> Dict:
    
        total_ports = len(results['ports'])
        open_ports = len(results['open_ports'])
        closed_ports = sum(1 for p in results['ports'].values() 
                          if p.get('state') == 'closed')
        filtered_ports = sum(1 for p in results['ports'].values() 
                           if p.get('state') == 'filtered')
        
        return {
            'total_ports': total_ports,
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'filtered_ports': filtered_ports,
            'scan_duration': results.get('duration', 0),
            'ports_per_second': total_ports / results.get('duration', 1)
        }
    
    def export_results(self, results: Dict, filename: str, format: str = 'json'):
     
        os.makedirs('reports', exist_ok=True)
        filepath = os.path.join('reports', filename)
        
        if format.lower() == 'json':
            with open(f"{filepath}.json", 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        
        elif format.lower() == 'txt':
            with open(f"{filepath}.txt", 'w', encoding='utf-8') as f:
                f.write(f"Port Tarama Raporu - {results['host']}\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Tarama Süresi: {results.get('duration', 0):.2f} saniye\n")
                f.write(f"Açık Portlar: {len(results['open_ports'])}\n\n")
                
                for port_num in sorted(results['open_ports']):
                    port_info = results['ports'][port_num]
                    f.write(f"Port {port_num}: {port_info.get('state', 'unknown')}\n")
                    f.write(f"  Servis: {port_info.get('service', 'unknown')}\n")
                    if port_info.get('banner'):
                        f.write(f"  Banner: {port_info['banner'][:100]}...\n")
                    f.write("\n")
    
    def get_host_info(self, host: str) -> Dict:
        info = {
            'host': host,
            'ip_address': '',
            'hostname': '',
            'is_alive': False
        }
        
        try:
            info['ip_address'] = socket.gethostbyname(host)
            
            try:
                info['hostname'] = socket.gethostbyaddr(info['ip_address'])[0]
            except:
                info['hostname'] = host
            
            ping_result = subprocess.run(
                ['ping', '-n', '1', '-w', '1000', info['ip_address']], 
                capture_output=True, text=True
            )
            info['is_alive'] = ping_result.returncode == 0
            
        except Exception as e:
            info['error'] = str(e)
        
        return info


if __name__ == "__main__":
    def progress_callback(progress, port, result):
        print(f"İlerleme: %{progress:.1f} - Port {port}: {result['state']}")
    
    scanner = PortScanner(timeout=0.5, max_threads=50)
    
    print("Port Scanner Test Başlatılıyor...")
    results = scanner.scan_range('127.0.0.1', 20, 100, callback=progress_callback)
    
    print(f"\nTarama Tamamlandı!")
    print(f"Açık Portlar: {results['open_ports']}")
    print(f"Tarama Süresi: {results['duration']:.2f} saniye")
    
    scanner.export_results(results, 'test_scan', 'json')