import ipaddress
import socket
import subprocess
import platform
import re
import json
import os
from typing import List, Dict, Optional, Tuple
import hashlib
import base64
from datetime import datetime

class IPUtils:
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False
    
    @staticmethod
    def is_valid_cidr(cidr: str) -> bool:
        try:
            ipaddress.IPv4Network(cidr, strict=False)
            return True
        except ipaddress.AddressValueError:
            return False
    
    @staticmethod
    def get_network_range(ip: str, netmask: str = "255.255.255.0") -> str:
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except:
            return f"{'.'.join(ip.split('.')[:-1])}.0/24"
    
    @staticmethod
    def expand_cidr(cidr: str) -> List[str]:
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except:
            return []
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        try:
            return ipaddress.IPv4Address(ip).is_private
        except:
            return False

class PortUtils:
    
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS-SSN",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
        995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy"
    }
    
    @staticmethod
    def get_service_name(port: int) -> str:
        return PortUtils.COMMON_PORTS.get(port, "unknown")
    
    @staticmethod
    def is_valid_port(port: int) -> bool:
        return 1 <= port <= 65535
    
    @staticmethod
    def parse_port_range(port_range: str) -> Tuple[int, int]:
        try:
            if '-' in port_range:
                start, end = port_range.split('-')
                return int(start.strip()), int(end.strip())
            else:
                port = int(port_range.strip())
                return port, port
        except:
            return 1, 1000
    
    @staticmethod
    def get_common_ports() -> List[int]:
        return list(PortUtils.COMMON_PORTS.keys())

class NetworkUtils:
    
    @staticmethod
    def ping_host(host: str, timeout: int = 1) -> Tuple[bool, float]:
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), host]
            
            start_time = datetime.now()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
            end_time = datetime.now()
            
            is_alive = result.returncode == 0
            response_time = (end_time - start_time).total_seconds() * 1000
            
            return is_alive, response_time
            
        except Exception:
            return False, 0.0
    
    @staticmethod
    def resolve_hostname(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ip
    
    @staticmethod
    def resolve_ip(hostname: str) -> str:
        try:
            return socket.gethostbyname(hostname)
        except:
            return hostname
    
    @staticmethod
    def get_local_ip() -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

class StringUtils:
    
    @staticmethod
    def clean_banner(banner: str) -> str:
        if not banner:
            return ""
        
        banner = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', banner)
        
        banner = ' '.join(banner.split())
        
        return banner[:200] 
    
    @staticmethod
    def extract_version(text: str) -> str:
        # Versiyon pattern'leri
        patterns = [
            r'(\d+\.\d+\.\d+\.\d+)', 
            r'(\d+\.\d+\.\d+)',     
            r'(\d+\.\d+)',          
            r'v(\d+\.\d+\.\d+)',     
            r'version\s+(\d+\.\d+)',  
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        if len(filename) > 200:
            filename = filename[:200]
        
        return filename
    
    @staticmethod
    def format_bytes(bytes_count: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"

class CryptoUtils:
    
    @staticmethod
    def calculate_md5(data: str) -> str:
        return hashlib.md5(data.encode()).hexdigest()
    
    @staticmethod
    def calculate_sha256(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def encode_base64(data: str) -> str:
        return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def decode_base64(data: str) -> str:
        try:
            return base64.b64decode(data).decode()
        except:
            return ""

class FileUtils:
    
    @staticmethod
    def ensure_directory(path: str):
        os.makedirs(path, exist_ok=True)
    
    @staticmethod
    def read_json_file(filepath: str) -> Dict:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    
    @staticmethod
    def write_json_file(filepath: str, data: Dict):
        try:
            FileUtils.ensure_directory(os.path.dirname(filepath))
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"JSON yazma hatası: {e}")
    
    @staticmethod
    def get_file_size(filepath: str) -> int:
        try:
            return os.path.getsize(filepath)
        except:
            return 0
    
    @staticmethod
    def is_file_exists(filepath: str) -> bool:
        return os.path.isfile(filepath)

class TimeUtils:
    
    @staticmethod
    def get_timestamp() -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    @staticmethod
    def get_readable_time() -> str:
        return datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.1f} saniye"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} dakika"
        else:
            hours = seconds / 3600
            return f"{hours:.1f} saat"

class ValidationUtils:
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        pattern = r'^https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])+)?(?:#(?:\w)+)?)?$'
        return re.match(pattern, url) is not None
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return re.match(pattern, domain) is not None

class LoggingUtils:
    
    @staticmethod
    def log_to_file(message: str, filename: str = "securipy.log"):
        try:
            FileUtils.ensure_directory("logs")
            log_path = os.path.join("logs", filename)
            
            timestamp = TimeUtils.get_readable_time()
            log_entry = f"[{timestamp}] {message}\n"
            
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(log_entry)
                
        except Exception as e:
            print(f"Log yazma hatası: {e}")
    
    @staticmethod
    def log_scan_start(scan_type: str, target: str):
        message = f"Tarama başlatıldı - Tür: {scan_type}, Hedef: {target}"
        LoggingUtils.log_to_file(message)
    
    @staticmethod
    def log_scan_end(scan_type: str, target: str, duration: float):
        message = f"Tarama tamamlandı - Tür: {scan_type}, Hedef: {target}, Süre: {duration:.2f}s"
        LoggingUtils.log_to_file(message)
    
    @staticmethod
    def log_error(error_message: str):
        message = f"HATA: {error_message}"
        LoggingUtils.log_to_file(message)

class ConfigUtils:
    
    DEFAULT_CONFIG = {
        "scan_settings": {
            "default_timeout": 1.0,
            "default_threads": 50,
            "max_threads": 200,
            "default_ports": "1-1000"
        },
        "ui_settings": {
            "theme": "default",
            "auto_save_reports": True,
            "show_progress": True
        },
        "security_settings": {
            "safe_mode": True,
            "log_scans": True,
            "max_scan_range": 65535
        }
    }
    
    @staticmethod
    def load_config() -> Dict:
        config_path = "config/settings.json"
        
        if FileUtils.is_file_exists(config_path):
            return FileUtils.read_json_file(config_path)
        else:
            ConfigUtils.save_config(ConfigUtils.DEFAULT_CONFIG)
            return ConfigUtils.DEFAULT_CONFIG
    
    @staticmethod
    def save_config(config: Dict):
        config_path = "config/settings.json"
        FileUtils.write_json_file(config_path, config)
    
    @staticmethod
    def get_setting(key_path: str, default_value=None):
        config = ConfigUtils.load_config()
        
        keys = key_path.split('.')
        value = config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default_value
    
    @staticmethod
    def set_setting(key_path: str, value):
        config = ConfigUtils.load_config()
        
        keys = key_path.split('.')
        current = config
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
        
        ConfigUtils.save_config(config)

if __name__ == "__main__":
    print("=== SecuriPy Utils Test ===")
    
    print(f"IP validation: {IPUtils.is_valid_ip('192.168.1.1')}")
    print(f"CIDR validation: {IPUtils.is_valid_cidr('192.168.1.0/24')}")
    
    local_ip = NetworkUtils.get_local_ip()
    print(f"Local IP: {local_ip}")
    
    print(f"Port 80 service: {PortUtils.get_service_name(80)}")
    
    version = StringUtils.extract_version("Apache/2.4.41 (Ubuntu)")
    print(f"Extracted version: {version}")
    
    print(f"Timestamp: {TimeUtils.get_timestamp()}")
    print(f"Readable time: {TimeUtils.get_readable_time()}")
    
    print("Test tamamlandı!")