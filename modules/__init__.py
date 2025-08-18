__version__ = "1.0.0"
__author__ = "SecuriPy Development Team"
__email__ = "developer@securipy.com"
__license__ = "MIT"
__description__ = "Kapsamlı Python Güvenlik Aracı Seti"

try:
    from .port_scanner import PortScanner
    from .vulnerability_scanner import VulnerabilityScanner, VulnerabilityLevel, Vulnerability
    from .network_analyzer import NetworkAnalyzer, NetworkDevice, NetworkSegment
    from .utils import (
        IPUtils, PortUtils, NetworkUtils, StringUtils, 
        CryptoUtils, FileUtils, TimeUtils, ValidationUtils,
        LoggingUtils, ConfigUtils
    )
    from .cli import SecuriPyCLI
    
    _import_success = True
    
except ImportError as e:
    print(f"⚠️ Modül import uyarısı: {e}")
    _import_success = False

__all__ = [
    'PortScanner',
    'VulnerabilityScanner', 
    'NetworkAnalyzer',
    'SecuriPyCLI',
    
    'Vulnerability',
    'VulnerabilityLevel', 
    'NetworkDevice',
    'NetworkSegment',
    
    'IPUtils',
    'PortUtils', 
    'NetworkUtils',
    'StringUtils',
    'CryptoUtils',
    'FileUtils',
    'TimeUtils',
    'ValidationUtils',
    'LoggingUtils',
    'ConfigUtils',
    
    '__version__',
    '__author__',
    '__license__'
]

def get_version():
    return __version__

def get_info():
    return {
        'name': 'SecuriPy',
        'version': __version__,
        'description': __description__,
        'author': __author__,
        'email': __email__,
        'license': __license__,
        'import_success': _import_success
    }

def check_dependencies():
    required_modules = [
        'requests', 'matplotlib', 'json', 'socket', 
        'threading', 'subprocess', 'ipaddress'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    return {
        'all_available': len(missing_modules) == 0,
        'missing': missing_modules,
        'available': [m for m in required_modules if m not in missing_modules]
    }

def create_default_scanner():
    if not _import_success:
        raise ImportError("Modüller düzgün yüklenmedi")
    
    return {
        'port_scanner': PortScanner(),
        'vuln_scanner': VulnerabilityScanner(), 
        'network_analyzer': NetworkAnalyzer()
    }

def _initialize_module():
    import os
    
    directories = ['reports', 'logs', 'data', 'config']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    deps = check_dependencies()
    if not deps['all_available']:
        print(f"⚠️ Eksik bağımlılıklar: {', '.join(deps['missing'])}")
        print("📦 Kurulum için: pip install -r requirements.txt")

_initialize_module()

def check_python_version():
    import sys
    
    required_version = (3, 8)
    current_version = sys.version_info[:2]
    
    if current_version < required_version:
        raise RuntimeError(
            f"SecuriPy Python {required_version[0]}.{required_version[1]} "
            f"veya üzeri gerektirir. Mevcut: {current_version[0]}.{current_version[1]}"
        )
    
    return True

try:
    check_python_version()
except RuntimeError as e:
    print(f"❌ {e}")

def print_debug_info():
    info = get_info()
    deps = check_dependencies()
    
    print(f"📦 {info['name']} v{info['version']}")
    print(f"📧 {info['author']} <{info['email']}>")
    print(f"📄 Lisans: {info['license']}")
    print(f"✅ Import Başarılı: {info['import_success']}")
    print(f"🔗 Tüm Bağımlılıklar: {deps['all_available']}")
    
    if not deps['all_available']:
        print(f"❌ Eksik: {', '.join(deps['missing'])}")

if __name__ == "__main__":
    print_debug_info()