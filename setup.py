# setup.py
"""
SecuriPy - Kapsamlı Güvenlik Aracı Seti
Kurulum ve Paketleme Betiği
"""
from setuptools import setup, find_packages
import os
import sys

# Python versiyon kontrolü
if sys.version_info < (3, 8):
    print("SecuriPy Python 3.8 veya üzeri gerektirir!")
    sys.exit(1)

# README dosyasını oku
def read_readme():
    try:
        with open("README.md", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "SecuriPy - Kapsamlı Güvenlik Aracı Seti"

# Requirements dosyasını oku
def read_requirements():
    try:
        with open("requirements.txt", "r", encoding="utf-8") as f:
            requirements = []
            for line in f:
                line = line.strip()
                # Yorum satırlarını ve boş satırları atla
                if line and not line.startswith("#"):
                    # Python built-in modüllerini atla
                    builtin_modules = [
                        "tkinter", "socket", "threading", "subprocess", 
                        "platform", "re", "json", "os", "sys", "time",
                        "datetime", "base64", "hashlib", "ipaddress",
                        "configparser", "pathlib", "smtplib", "urllib",
                        "http", "ssl", "email", "mimetypes", "logging",
                        "unittest", "concurrent", "dataclasses", "typing"
                    ]
                    
                    module_name = line.split(">=")[0].split("==")[0].split("~=")[0].strip()
                    
                    if module_name not in builtin_modules:
                        requirements.append(line)
            
            return requirements
    except FileNotFoundError:
        # Varsayılan requirements (hashlib kaldırıldı)
        return [
            "requests>=2.28.0",
            "scapy>=2.4.5",
            "python-nmap>=0.7.1",
            "beautifulsoup4>=4.11.0",
            "cryptography>=3.4.8",
            "paramiko>=2.11.0",
            "colorama>=0.4.5",
            "tqdm>=4.64.0",
            "pillow>=9.2.0",
            "matplotlib>=3.5.0",
            "numpy>=1.21.0",
            "psutil>=5.9.0"
        ]

# Package setup
setup(
    # Temel bilgiler
    name="securipy",
    version="1.0.0",
    author="SecuriPy Team",
    author_email="info@securipy.com",
    description="Kapsamlı güvenlik aracı seti - Network scanning, vulnerability assessment ve penetration testing araçları",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/securipy",
    
    # Paket bilgileri - proje yapınıza göre düzeltildi
    packages=["modules"],  # find_packages() yerine manuel tanım
    package_data={
        "": [
            "data/*.json",
            "config/*.json",
            "README.md"
        ]
    },
    include_package_data=True,
    
    # Data dosyaları - proje yapınıza göre
    data_files=[
        ("data", [
            "data/common_ports.json",
            "data/vulnerabilities.json", 
            "data/banners.json"
        ]),
        ("config", [
            "config/settings.json"
        ]),
        (".", ["README.md"])
    ],
    
    # Bağımlılıklar
    python_requires=">=3.8",
    install_requires=read_requirements(),
    
    # Entry points - proje yapınıza göre düzeltildi
    entry_points={
        'console_scripts': [
            'securipy=main:main',
            'securipy-cli=modules.cli:main',
            'securipy-gui=main:main',
            'securipy-net=modules.network_analyzer:main',
            'securipy-scan=modules.port_scanner:main',
            'securipy-vuln=modules.vulnerability_scanner:main',
        ],
        'gui_scripts': [
            'securipy-desktop=main:main',
        ]
    },
    
    # Metadata
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Utilities"
    ],
    
    keywords="security penetration-testing network-scanner vulnerability-scanner cybersecurity",
    license="MIT",
    zip_safe=False,
)
