# SecuriPy Ana GUI Dosyası 
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import json
import os
import sys
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
import subprocess
import webbrowser

# Modülleri import et
try:
    from modules.port_scanner import PortScanner
    from modules.vulnerability_scanner import VulnerabilityScanner
    from modules.network_analyzer import NetworkAnalyzer
except ImportError as e:
    print(f"Modül import hatası: {e}")
    print("Lütfen modules klasörünün doğru konumda olduğundan emin olun.")
    sys.exit(1)

class SecuriPyGUI:
    """
    SecuriPy - Kapsamlı Güvenlik Aracı Seti
    Ana GUI sınıfı
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("SecuriPy - Kapsamlı Güvenlik Aracı Seti v1.0")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        # Stil yapılandırması
        self.setup_styles()
        
        # Tarayıcı nesneleri
        self.port_scanner = PortScanner()
        self.vuln_scanner = VulnerabilityScanner()
        self.network_analyzer = NetworkAnalyzer()
        
        # Tarama durumu
        self.scan_running = False
        self.current_scan_thread = None
        
        # Sonuç verilerini sakla
        self.last_port_results = None
        self.last_vuln_results = None
        self.last_network_results = None
        
        # GUI oluştur
        self.create_widgets()
        
        # Dizinleri oluştur
        self.create_directories()
    
    def setup_styles(self):
        """GUI stillerini ayarlar"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Özel renkler
        style.configure('Title.TLabel', 
                       font=('Arial', 16, 'bold'), 
                       background='#2c3e50', 
                       foreground='#ecf0f1')
        
        style.configure('Subtitle.TLabel', 
                       font=('Arial', 12, 'bold'), 
                       background='#34495e', 
                       foreground='#ecf0f1')
        
        style.configure('Custom.TButton',
                       font=('Arial', 10, 'bold'),
                       background='#3498db',
                       foreground='white')
        
        style.map('Custom.TButton',
                 background=[('active', '#2980b9')])
        
        style.configure('Success.TButton',
                       background='#27ae60')
        
        style.configure('Danger.TButton',
                       background='#e74c3c')
    
    def create_directories(self):
        """Gerekli dizinleri oluşturur"""
        dirs = ['reports', 'data', 'config']
        for dir_name in dirs:
            os.makedirs(dir_name, exist_ok=True)
        
        # Örnek veri dosyalarını oluştur
        self.create_sample_data_files()
    
    def create_sample_data_files(self):
        """Örnek veri dosyalarını oluşturur"""
        # common_ports.json
        common_ports = {
            "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
            "53": "DNS", "80": "HTTP", "110": "POP3", "143": "IMAP",
            "443": "HTTPS", "993": "IMAPS", "995": "POP3S", "3389": "RDP",
            "3306": "MySQL", "5432": "PostgreSQL", "1433": "MSSQL",
            "5900": "VNC", "8080": "HTTP-Alt", "445": "SMB"
        }
        
        with open('data/common_ports.json', 'w', encoding='utf-8') as f:
            json.dump(common_ports, f, indent=2, ensure_ascii=False)
    
    def create_widgets(self):
        """Ana widget'ları oluşturur"""
        # Ana başlık
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        title_frame.pack(fill='x', padx=10, pady=5)
        title_frame.pack_propagate(False)
        
        title_label = ttk.Label(title_frame, 
                               text="🛡️ SecuriPy - Kapsamlı Güvenlik Aracı Seti", 
                               style='Title.TLabel')
        title_label.pack(expand=True)
        
        # Ana container
        main_container = tk.Frame(self.root, bg='#2c3e50')
        main_container.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Sol panel - Kontroller
        self.create_control_panel(main_container)
        
        # Sağ panel - Sonuçlar
        self.create_results_panel(main_container)
        
        # Alt panel - Durum çubuğu
        self.create_status_panel()
    
    def create_control_panel(self, parent):
        """Sol kontrol panelini oluşturur"""
        control_frame = tk.Frame(parent, bg='#34495e', width=400)
        control_frame.pack(side='left', fill='y', padx=(0, 10))
        control_frame.pack_propagate(False)
        
        # Notebook için tab'ler
        notebook = ttk.Notebook(control_frame)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Port Scanner Tab
        self.create_port_scanner_tab(notebook)
        
        # Vulnerability Scanner Tab
        self.create_vulnerability_scanner_tab(notebook)
        
        # Network Analyzer Tab
        self.create_network_analyzer_tab(notebook)
    
    def create_port_scanner_tab(self, notebook):
        """Port Scanner tab'ını oluşturur"""
        port_frame = ttk.Frame(notebook)
        notebook.add(port_frame, text="Port Tarama")
        
        # Hedef IP girişi
        ttk.Label(port_frame, text="Hedef IP/Domain:", font=('Arial', 10, 'bold')).pack(anchor='w', pady=(10, 5))
        self.target_ip_var = tk.StringVar(value="127.0.0.1")
        self.target_ip_entry = ttk.Entry(port_frame, textvariable=self.target_ip_var, width=30)
        self.target_ip_entry.pack(fill='x', pady=(0, 10))
        
        # Port aralığı
        port_range_frame = tk.Frame(port_frame, bg='#34495e')
        port_range_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(port_range_frame, text="Port Aralığı:", font=('Arial', 10, 'bold')).pack(anchor='w')
        
        range_frame = tk.Frame(port_range_frame, bg='#34495e')
        range_frame.pack(fill='x', pady=5)
        
        self.start_port_var = tk.StringVar(value="1")
        self.end_port_var = tk.StringVar(value="1000")
        
        ttk.Label(range_frame, text="Başlangıç:").pack(side='left')
        ttk.Entry(range_frame, textvariable=self.start_port_var, width=8).pack(side='left', padx=(5, 10))
        ttk.Label(range_frame, text="Bitiş:").pack(side='left')
        ttk.Entry(range_frame, textvariable=self.end_port_var, width=8).pack(side='left', padx=5)
        
        # Tarama türü
        ttk.Label(port_frame, text="Tarama Türü:", font=('Arial', 10, 'bold')).pack(anchor='w', pady=(10, 5))
        self.scan_type_var = tk.StringVar(value="tcp")
        
        scan_type_frame = tk.Frame(port_frame, bg='#34495e')
        scan_type_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Radiobutton(scan_type_frame, text="TCP", variable=self.scan_type_var, value="tcp").pack(side='left')
        ttk.Radiobutton(scan_type_frame, text="UDP", variable=self.scan_type_var, value="udp").pack(side='left', padx=10)
        
        # Hızlı tarama seçenekleri
        quick_scan_frame = tk.Frame(port_frame, bg='#34495e')
        quick_scan_frame.pack(fill='x', pady=10)
        
        ttk.Button(quick_scan_frame, text="Yaygın Portlar", 
                  command=self.quick_common_scan, style='Custom.TButton').pack(side='left', padx=(0, 5))
        ttk.Button(quick_scan_frame, text="Tüm Portlar", 
                  command=self.quick_full_scan, style='Danger.TButton').pack(side='left')
        
        # Gelişmiş seçenekler
        advanced_frame = ttk.LabelFrame(port_frame, text="Gelişmiş Seçenekler")
        advanced_frame.pack(fill='x', pady=10)
        
        # Thread sayısı
        thread_frame = tk.Frame(advanced_frame)
        thread_frame.pack(fill='x', pady=5)
        
        ttk.Label(thread_frame, text="Thread Sayısı:").pack(side='left')
        self.thread_count_var = tk.StringVar(value="50")
        thread_spinbox = tk.Spinbox(thread_frame, from_=1, to=200, textvariable=self.thread_count_var, width=10)
        thread_spinbox.pack(side='right')
        
        # Timeout
        timeout_frame = tk.Frame(advanced_frame)
        timeout_frame.pack(fill='x', pady=5)
        
        ttk.Label(timeout_frame, text="Timeout (saniye):").pack(side='left')
        self.timeout_var = tk.StringVar(value="1.0")
        timeout_spinbox = tk.Spinbox(timeout_frame, from_=0.1, to=10.0, increment=0.1, 
                                   textvariable=self.timeout_var, width=10)
        timeout_spinbox.pack(side='right')
        
        # Banner grabbing
        self.banner_grab_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_frame, text="Banner Grabbing", 
                       variable=self.banner_grab_var).pack(anchor='w', pady=5)
        
        # Tarama başlat butonu
        self.port_scan_btn = ttk.Button(port_frame, text="🚀 Port Taraması Başlat", 
                                       command=self.start_port_scan, style='Success.TButton')
        self.port_scan_btn.pack(fill='x', pady=20)
    
    def create_vulnerability_scanner_tab(self, notebook):
        """Vulnerability Scanner tab'ını oluşturur"""
        vuln_frame = ttk.Frame(notebook)
        notebook.add(vuln_frame, text="Zafiyet Tarama")
        
        # Hedef bilgileri
        ttk.Label(vuln_frame, text="Hedef Sistem:", font=('Arial', 10, 'bold')).pack(anchor='w', pady=(10, 5))
        self.vuln_target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(vuln_frame, textvariable=self.vuln_target_var, width=30).pack(fill='x', pady=(0, 10))
        
        # Tarama türleri
        scan_types_frame = ttk.LabelFrame(vuln_frame, text="Tarama Türleri")
        scan_types_frame.pack(fill='x', pady=10)
        
        self.web_vuln_var = tk.BooleanVar(value=True)
        self.service_vuln_var = tk.BooleanVar(value=True)
        self.config_vuln_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(scan_types_frame, text="Web Uygulama Güvenlik Açıkları", 
                       variable=self.web_vuln_var).pack(anchor='w', pady=2)
        ttk.Checkbutton(scan_types_frame, text="Servis Güvenlik Açıkları", 
                       variable=self.service_vuln_var).pack(anchor='w', pady=2)
        ttk.Checkbutton(scan_types_frame, text="Konfigürasyon Kontrolü", 
                       variable=self.config_vuln_var).pack(anchor='w', pady=2)
        
        # Şiddet seviyesi filtresi
        severity_frame = ttk.LabelFrame(vuln_frame, text="Minimum Şiddet Seviyesi")
        severity_frame.pack(fill='x', pady=10)
        
        self.severity_var = tk.StringVar(value="low")
        severities = [("Tümü", "low"), ("Orta", "medium"), ("Yüksek", "high"), ("Kritik", "critical")]
        
        for text, value in severities:
            ttk.Radiobutton(severity_frame, text=text, variable=self.severity_var, 
                           value=value).pack(side='left', padx=5)
        
        # CVE veritabanı güncelleme
        update_frame = tk.Frame(vuln_frame)
        update_frame.pack(fill='x', pady=10)
        
        ttk.Button(update_frame, text="🔄 CVE DB Güncelle", 
                  command=self.update_cve_db).pack(side='left')
        
        self.last_update_label = ttk.Label(update_frame, text="Son güncelleme: Bilinmiyor")
        self.last_update_label.pack(side='right')
        
        # Tarama başlat
        self.vuln_scan_btn = ttk.Button(vuln_frame, text="🔍 Güvenlik Açığı Taraması", 
                                       command=self.start_vulnerability_scan, style='Success.TButton')
        self.vuln_scan_btn.pack(fill='x', pady=20)
    
    def create_network_analyzer_tab(self, notebook):
        """Network Analyzer tab'ını oluşturur"""
        network_frame = ttk.Frame(notebook)
        notebook.add(network_frame, text="Ağ Analizi")
        
        # Ağ aralığı
        ttk.Label(network_frame, text="Ağ Aralığı (CIDR):", font=('Arial', 10, 'bold')).pack(anchor='w', pady=(10, 5))
        self.network_range_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(network_frame, textvariable=self.network_range_var, width=30).pack(fill='x', pady=(0, 10))
        
        # Hızlı ağ seçenekleri
        quick_network_frame = tk.Frame(network_frame)
        quick_network_frame.pack(fill='x', pady=10)
        
        ttk.Button(quick_network_frame, text="Yerel Ağ", 
                  command=self.detect_local_network).pack(side='left', padx=(0, 5))
        ttk.Button(quick_network_frame, text="Otomatik Tespit", 
                  command=self.auto_detect_network).pack(side='left')
        
        # Tarama seçenekleri
        scan_options_frame = ttk.LabelFrame(network_frame, text="Tarama Seçenekleri")
        scan_options_frame.pack(fill='x', pady=10)
        
        self.ping_sweep_var = tk.BooleanVar(value=True)
        self.port_discovery_var = tk.BooleanVar(value=True)
        self.os_detection_var = tk.BooleanVar(value=True)
        self.service_detection_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(scan_options_frame, text="Ping Sweep", 
                       variable=self.ping_sweep_var).pack(anchor='w', pady=2)
        ttk.Checkbutton(scan_options_frame, text="Port Keşfi", 
                       variable=self.port_discovery_var).pack(anchor='w', pady=2)
        ttk.Checkbutton(scan_options_frame, text="OS Tespiti", 
                       variable=self.os_detection_var).pack(anchor='w', pady=2)
        ttk.Checkbutton(scan_options_frame, text="Servis Tespiti", 
                       variable=self.service_detection_var).pack(anchor='w', pady=2)
        
        # Network performans ayarları
        perf_frame = ttk.LabelFrame(network_frame, text="Performans Ayarları")
        perf_frame.pack(fill='x', pady=10)
        
        # Ping timeout
        ping_timeout_frame = tk.Frame(perf_frame)
        ping_timeout_frame.pack(fill='x', pady=5)
        
        ttk.Label(ping_timeout_frame, text="Ping Timeout:").pack(side='left')
        self.ping_timeout_var = tk.StringVar(value="1.0")
        tk.Spinbox(ping_timeout_frame, from_=0.1, to=5.0, increment=0.1, 
                  textvariable=self.ping_timeout_var, width=10).pack(side='right')
        
        # Max threads
        max_threads_frame = tk.Frame(perf_frame)
        max_threads_frame.pack(fill='x', pady=5)
        
        ttk.Label(max_threads_frame, text="Max Threads:").pack(side='left')
        self.max_threads_var = tk.StringVar(value="50")
        tk.Spinbox(max_threads_frame, from_=1, to=200, 
                  textvariable=self.max_threads_var, width=10).pack(side='right')
        
        # Tarama başlat
        self.network_scan_btn = ttk.Button(network_frame, text="🕸️ Ağ Analizi Başlat", 
                                          command=self.start_network_analysis, style='Success.TButton')
        self.network_scan_btn.pack(fill='x', pady=20)
    
    def create_results_panel(self, parent):
        """Sağ sonuçlar panelini oluşturur"""
        results_frame = tk.Frame(parent, bg='#ecf0f1')
        results_frame.pack(side='right', fill='both', expand=True)
        
        # Sonuçlar notebook
        self.results_notebook = ttk.Notebook(results_frame)
        self.results_notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Port scan sonuçları
        self.create_port_results_tab()
        
        # Vulnerability sonuçları
        self.create_vuln_results_tab()
        
        # Network analysis sonuçları
        self.create_network_results_tab()
        
        # Raporlar tab'ı
        self.create_reports_tab()
    
    def create_port_results_tab(self):
        """Port tarama sonuçları tab'ı"""
        port_results_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(port_results_frame, text="Port Tarama")
        
        # Üst bilgi paneli
        info_frame = tk.Frame(port_results_frame, bg='#3498db', height=60)
        info_frame.pack(fill='x', pady=(0, 10))
        info_frame.pack_propagate(False)
        
        self.port_scan_info = tk.Label(info_frame, text="Port taraması başlatılmadı", 
                                      bg='#3498db', fg='white', font=('Arial', 12, 'bold'))
        self.port_scan_info.pack(expand=True)
        
        # İlerleme çubuğu
        self.port_progress = ttk.Progressbar(port_results_frame, mode='determinate')
        self.port_progress.pack(fill='x', pady=(0, 10))
        
        # Sonuçlar tablosu
        columns = ('Port', 'Durum', 'Servis', 'Banner', 'Versiyon')
        self.port_tree = ttk.Treeview(port_results_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.port_tree.heading(col, text=col)
            self.port_tree.column(col, width=120)
        
        # Scrollbar
        port_scrollbar = ttk.Scrollbar(port_results_frame, orient='vertical', command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=port_scrollbar.set)
        
        # Pack tree ve scrollbar
        tree_frame = tk.Frame(port_results_frame)
        tree_frame.pack(fill='both', expand=True)
        
        self.port_tree.pack(side='left', fill='both', expand=True)
        port_scrollbar.pack(side='right', fill='y')
    
    def create_vuln_results_tab(self):
        """Güvenlik açığı sonuçları tab'ı"""
        vuln_results_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(vuln_results_frame, text="Güvenlik Açıkları")
        
        # Üst özet paneli
        summary_frame = tk.Frame(vuln_results_frame, bg='#e74c3c', height=80)
        summary_frame.pack(fill='x', pady=(0, 10))
        summary_frame.pack_propagate(False)
        
        self.vuln_summary = tk.Label(summary_frame, text="Güvenlik açığı taraması başlatılmadı", 
                                    bg='#e74c3c', fg='white', font=('Arial', 12, 'bold'))
        self.vuln_summary.pack(expand=True)
        
        # Severity istatistikleri
        stats_frame = tk.Frame(vuln_results_frame)
        stats_frame.pack(fill='x', pady=(0, 10))
        
        self.critical_count = tk.Label(stats_frame, text="Critical: 0", bg='#c0392b', fg='white', padx=10, pady=5)
        self.critical_count.pack(side='left', padx=2)
        
        self.high_count = tk.Label(stats_frame, text="High: 0", bg='#e67e22', fg='white', padx=10, pady=5)
        self.high_count.pack(side='left', padx=2)
        
        self.medium_count = tk.Label(stats_frame, text="Medium: 0", bg='#f39c12', fg='white', padx=10, pady=5)
        self.medium_count.pack(side='left', padx=2)
        
        self.low_count = tk.Label(stats_frame, text="Low: 0", bg='#27ae60', fg='white', padx=10, pady=5)
        self.low_count.pack(side='left', padx=2)
        
        # Güvenlik açıkları tablosu
        vuln_columns = ('CVE ID', 'Başlık', 'Severity', 'CVSS', 'Servis', 'Açıklama')
        self.vuln_tree = ttk.Treeview(vuln_results_frame, columns=vuln_columns, show='headings', height=12)
        
        for col in vuln_columns:
            self.vuln_tree.heading(col, text=col)
            if col == 'Açıklama':
                self.vuln_tree.column(col, width=200)
            else:
                self.vuln_tree.column(col, width=100)
        
        # Scrollbar
        vuln_scrollbar = ttk.Scrollbar(vuln_results_frame, orient='vertical', command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=vuln_scrollbar.set)
        
        vuln_tree_frame = tk.Frame(vuln_results_frame)
        vuln_tree_frame.pack(fill='both', expand=True)
        
        self.vuln_tree.pack(side='left', fill='both', expand=True)
        vuln_scrollbar.pack(side='right', fill='y')
        
        # Detay paneli
        detail_frame = tk.Frame(vuln_results_frame, height=100)
        detail_frame.pack(fill='x', pady=10)
        detail_frame.pack_propagate(False)
        
        ttk.Label(detail_frame, text="Güvenlik Açığı Detayları:", font=('Arial', 10, 'bold')).pack(anchor='w')
        self.vuln_detail_text = scrolledtext.ScrolledText(detail_frame, height=4, wrap=tk.WORD)
        self.vuln_detail_text.pack(fill='both', expand=True)
        
        # Tree selection event
        self.vuln_tree.bind('<<TreeviewSelect>>', self.on_vuln_select)
    
    def create_network_results_tab(self):
        """Network analiz sonuçları tab'ı"""
        network_results_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(network_results_frame, text="Ağ Analizi")
        
        # Özet paneli
        network_summary_frame = tk.Frame(network_results_frame, bg='#16a085', height=60)
        network_summary_frame.pack(fill='x', pady=(0, 10))
        network_summary_frame.pack_propagate(False)
        
        self.network_summary = tk.Label(network_summary_frame, text="Ağ analizi başlatılmadı", 
                                       bg='#16a085', fg='white', font=('Arial', 12, 'bold'))
        self.network_summary.pack(expand=True)
        
        # İlerleme çubuğu
        self.network_progress = ttk.Progressbar(network_results_frame, mode='determinate')
        self.network_progress.pack(fill='x', pady=(0, 10))
        
        # Bulunan cihazlar tablosu
        device_columns = ('IP', 'Hostname', 'MAC', 'OS', 'Vendor', 'Portlar', 'Ping (ms)')
        self.device_tree = ttk.Treeview(network_results_frame, columns=device_columns, show='headings', height=10)
        
        for col in device_columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=100)
        
        device_scrollbar = ttk.Scrollbar(network_results_frame, orient='vertical', command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=device_scrollbar.set)
        
        device_tree_frame = tk.Frame(network_results_frame)
        device_tree_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        self.device_tree.pack(side='left', fill='both', expand=True)
        device_scrollbar.pack(side='right', fill='y')
        
        # Grafikler frame'i
        charts_frame = tk.Frame(network_results_frame, height=200)
        charts_frame.pack(fill='x')
        charts_frame.pack_propagate(False)
        
        # Matplotlib canvas için yer
        self.network_chart_frame = charts_frame
    
    def create_reports_tab(self):
        """Raporlar tab'ı"""
        reports_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(reports_frame, text="📊 Raporlar")
        
        # Rapor türleri
        report_types_frame = ttk.LabelFrame(reports_frame, text="Rapor Türleri")
        report_types_frame.pack(fill='x', padx=10, pady=10)
        
        self.json_report_var = tk.BooleanVar(value=True)
        self.html_report_var = tk.BooleanVar(value=True)
        self.pdf_report_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(report_types_frame, text="JSON Raporu", variable=self.json_report_var).pack(anchor='w')
        ttk.Checkbutton(report_types_frame, text="HTML Raporu", variable=self.html_report_var).pack(anchor='w')
        ttk.Checkbutton(report_types_frame, text="PDF Raporu", variable=self.pdf_report_var).pack(anchor='w')
        
        # Rapor oluşturma
        report_actions_frame = tk.Frame(reports_frame)
        report_actions_frame.pack(fill='x', padx=10, pady=20)
        
        ttk.Button(report_actions_frame, text="📄 Rapor Oluştur", 
                  command=self.generate_reports).pack(side='left', padx=(0, 10))
        ttk.Button(report_actions_frame, text="📁 Raporları Aç", 
                  command=self.open_reports_folder).pack(side='left')
        
        # Mevcut raporlar listesi
        reports_list_frame = ttk.LabelFrame(reports_frame, text="Mevcut Raporlar")
        reports_list_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.reports_listbox = tk.Listbox(reports_list_frame)
        self.reports_listbox.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Raporları yenile
        ttk.Button(reports_list_frame, text="🔄 Yenile", 
                  command=self.refresh_reports_list).pack(pady=5)
        
        # İlk yükleme
        self.refresh_reports_list()
    
    def create_status_panel(self):
        """Alt durum panelini oluşturur"""
        status_frame = tk.Frame(self.root, bg='#34495e', height=30)
        status_frame.pack(fill='x', side='bottom')
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="Hazır", bg='#34495e', fg='#ecf0f1')
        self.status_label.pack(side='left', padx=10, pady=5)
        
        # Durdur butonu
        self.stop_scan_btn = ttk.Button(status_frame, text="⏹️ Durdur", 
                                       command=self.stop_scan, style='Danger.TButton')
        self.stop_scan_btn.pack(side='left', padx=10)
        self.stop_scan_btn.pack_forget()  # Başlangıçta gizle
        
        # Saat
        self.time_label = tk.Label(status_frame, text="", bg='#34495e', fg='#ecf0f1')
        self.time_label.pack(side='right', padx=10, pady=5)
        
        self.update_time()
    
    def update_time(self):
        """Saati günceller"""
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
    
    # ===== EVENT HANDLERS =====
    
    def quick_common_scan(self):
        """Yaygın portlar için hızlı tarama"""
        self.start_port_var.set("1")
        self.end_port_var.set("1024")
        self.thread_count_var.set("100")
        self.timeout_var.set("0.5")
    
    def quick_full_scan(self):
        """Tüm portlar için tarama"""
        self.start_port_var.set("1")
        self.end_port_var.set("65535")
        self.thread_count_var.set("200")
        self.timeout_var.set("0.3")
    
    def detect_local_network(self):
        """Yerel ağı otomatik tespit eder"""
        try:
            interfaces = self.network_analyzer.get_network_interfaces()
            for interface in interfaces:
                if interface.get('ip') and not interface['ip'].startswith('127.'):
                    ip = interface['ip']
                    # /24 subnet varsay
                    network = '.'.join(ip.split('.')[:-1]) + '.0/24'
                    self.network_range_var.set(network)
                    break
        except Exception as e:
            messagebox.showerror("Hata", f"Yerel ağ tespit edilemedi: {str(e)}")
    
    def auto_detect_network(self):
        """Ağı otomatik tespit eder"""
        self.detect_local_network()
    
    def update_cve_db(self):
        """CVE veritabanını günceller"""
        self.status_label.config(text="CVE veritabanı güncelleniyor...")
        # Simüle edilmiş güncelleme
        self.root.after(2000, lambda: self.status_label.config(text="CVE veritabanı güncellendi"))
        self.last_update_label.config(text=f"Son güncelleme: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    
    def on_vuln_select(self, event):
        """Güvenlik açığı seçildiğinde detayları göster"""
        selection = self.vuln_tree.selection()
        if selection:
            item = self.vuln_tree.item(selection[0])
            values = item['values']
            
            detail_text = f"CVE ID: {values[0]}\n"
            detail_text += f"Başlık: {values[1]}\n"
            detail_text += f"Severity: {values[2]} (CVSS: {values[3]})\n"
            detail_text += f"Etkilenen Servis: {values[4]}\n"
            detail_text += f"Açıklama: {values[5]}\n"
            
            self.vuln_detail_text.delete(1.0, tk.END)
            self.vuln_detail_text.insert(1.0, detail_text)
    
    def start_port_scan(self):
        """Port taramasını başlatır"""
        if self.scan_running:
            messagebox.showwarning("Uyarı", "Bir tarama zaten çalışıyor!")
            return
        
        target = self.target_ip_var.get().strip()
        if not target:
            messagebox.showerror("Hata", "Hedef IP adresi giriniz!")
            return
        
        try:
            start_port = int(self.start_port_var.get())
            end_port = int(self.end_port_var.get())
            
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError("Geçersiz port aralığı!")
            
            thread_count = int(self.thread_count_var.get())
            timeout = float(self.timeout_var.get())
            protocol = self.scan_type_var.get()
            
            # Tarama thread'ini başlat
            self.scan_running = True
            self.stop_scan_btn.pack(side='left', padx=10)
            self.port_scan_btn.config(state='disabled')
            
            self.current_scan_thread = threading.Thread(
                target=self._run_port_scan,
                args=(target, start_port, end_port, protocol, thread_count, timeout)
            )
            self.current_scan_thread.daemon = True
            self.current_scan_thread.start()
            
        except ValueError as e:
            messagebox.showerror("Hata", f"Geçersiz değer: {str(e)}")
    
    def _run_port_scan(self, target, start_port, end_port, protocol, thread_count, timeout):
        """Port taramasını çalıştırır"""
        try:
            # Scanner ayarları
            self.port_scanner.timeout = timeout
            self.port_scanner.max_threads = thread_count
            
            # UI güncelleme
            self.root.after(0, lambda: self.port_scan_info.config(
                text=f"Port taraması çalışıyor: {target} ({start_port}-{end_port})"
            ))
            
            # Callback fonksiyonu
            def progress_callback(progress, port, result):
                if not self.scan_running:
                    return
                
                self.root.after(0, lambda: self.port_progress.config(value=progress))
                
                # Açık port bulunursa hemen ekle
                if result and result.get('state') == 'open':
                    self.root.after(0, lambda: self._add_port_result(result))
            
            # Taramayı başlat
            results = self.port_scanner.scan_range(
                target, start_port, end_port, protocol, progress_callback
            )
            
            if self.scan_running:
                self.last_port_results = results
                self.root.after(0, lambda: self._update_port_results(results))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Hata", f"Port taraması hatası: {str(e)}"))
        finally:
            self.root.after(0, self._port_scan_finished)
    
    def _add_port_result(self, result):
        """Tek bir port sonucunu tabloya ekler"""
        port = result['port']
        state = result['state']
        service = result.get('service', 'unknown')
        banner = result.get('banner', '')[:50]  # İlk 50 karakter
        version = result.get('version', '')
        
        self.port_tree.insert('', 'end', values=(port, state, service, banner, version))
    
    def _update_port_results(self, results):
        """Port tarama sonuçlarını günceller"""
        # Tabloyu temizle
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)
        
        # Sonuçları ekle
        for port_num in sorted(results['open_ports']):
            port_info = results['ports'][port_num]
            self._add_port_result(port_info)
        
        # Özet bilgileri güncelle
        total_ports = len(results['ports'])
        open_ports = len(results['open_ports'])
        duration = results.get('duration', 0)
        
        summary_text = f"Tarama tamamlandı! {open_ports}/{total_ports} port açık - {duration:.2f} saniye"
        self.port_scan_info.config(text=summary_text)
    
    def _port_scan_finished(self):
        """Port taraması bittiğinde çağrılır"""
        self.scan_running = False
        self.port_scan_btn.config(state='normal')
        self.stop_scan_btn.pack_forget()
        self.port_progress.config(value=100)
        self.status_label.config(text="Port taraması tamamlandı")
    
    def start_vulnerability_scan(self):
        """Güvenlik açığı taramasını başlatır"""
        if self.scan_running:
            messagebox.showwarning("Uyarı", "Bir tarama zaten çalışıyor!")
            return
        
        target = self.vuln_target_var.get().strip()
        if not target:
            messagebox.showerror("Hata", "Hedef sistem adresi giriniz!")
            return
        
        self.scan_running = True
        self.stop_scan_btn.pack(side='left', padx=10)
        self.vuln_scan_btn.config(state='disabled')
        
        self.current_scan_thread = threading.Thread(
            target=self._run_vulnerability_scan,
            args=(target,)
        )
        self.current_scan_thread.daemon = True
        self.current_scan_thread.start()
    
    def _run_vulnerability_scan(self, target):
        """Güvenlik açığı taramasını çalıştırır"""
        try:
            self.root.after(0, lambda: self.vuln_summary.config(
                text=f"Güvenlik açığı taraması çalışıyor: {target}"
            ))
            
            vulnerabilities = []
            
            # Web uygulaması taraması
            if self.web_vuln_var.get():
                web_vulns = self.vuln_scanner._scan_web_vulnerabilities(target, 80)
                vulnerabilities.extend(web_vulns)
            
            # Servis taraması (port tarama sonuçlarını kullan)
            if self.service_vuln_var.get() and self.last_port_results:
                for port_num in self.last_port_results['open_ports']:
                    port_info = self.last_port_results['ports'][port_num]
                    service = port_info.get('service', 'unknown')
                    version = port_info.get('version', '')
                    
                    service_vulns = self.vuln_scanner.scan_service_vulnerabilities(
                        target, port_num, service, version
                    )
                    vulnerabilities.extend(service_vulns)
            
            if self.scan_running:
                self.last_vuln_results = vulnerabilities
                self.root.after(0, lambda: self._update_vulnerability_results(vulnerabilities))
                
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Hata", f"Güvenlik taraması hatası: {str(e)}"))
        finally:
            self.root.after(0, self._vulnerability_scan_finished)
    
    def _update_vulnerability_results(self, vulnerabilities):
        """Güvenlik açığı sonuçlarını günceller"""
        # Tabloyu temizle
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        # Severity sayaçları
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        # Sonuçları ekle
        for vuln in vulnerabilities:
            severity = vuln.severity.value.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            self.vuln_tree.insert('', 'end', values=(
                vuln.cve_id,
                vuln.title[:50],
                vuln.severity.value,
                vuln.cvss_score,
                vuln.affected_service,
                vuln.description[:100]
            ))
        
        # Severity istatistiklerini güncelle
        self.critical_count.config(text=f"Critical: {severity_counts['critical']}")
        self.high_count.config(text=f"High: {severity_counts['high']}")
        self.medium_count.config(text=f"Medium: {severity_counts['medium']}")
        self.low_count.config(text=f"Low: {severity_counts['low']}")
        
        # Özet güncelle
        total_vulns = len(vulnerabilities)
        self.vuln_summary.config(text=f"Tarama tamamlandı! {total_vulns} güvenlik açığı bulundu")
    
    def _vulnerability_scan_finished(self):
        """Güvenlik açığı taraması bittiğinde çağrılır"""
        self.scan_running = False
        self.vuln_scan_btn.config(state='normal')
        self.stop_scan_btn.pack_forget()
        self.status_label.config(text="Güvenlik açığı taraması tamamlandı")
    
    def start_network_analysis(self):
        """Ağ analizi başlatır"""
        if self.scan_running:
            messagebox.showwarning("Uyarı", "Bir tarama zaten çalışıyor!")
            return
        
        network_range = self.network_range_var.get().strip()
        if not network_range:
            messagebox.showerror("Hata", "Ağ aralığı giriniz!")
            return
        
        self.scan_running = True
        self.stop_scan_btn.pack(side='left', padx=10)
        self.network_scan_btn.config(state='disabled')
        
        # Ayarları uygula
        self.network_analyzer.timeout = float(self.ping_timeout_var.get())
        self.network_analyzer.max_threads = int(self.max_threads_var.get())
        
        self.current_scan_thread = threading.Thread(
            target=self._run_network_analysis,
            args=(network_range,)
        )
        self.current_scan_thread.daemon = True
        self.current_scan_thread.start()
    
    def _run_network_analysis(self, network_range):
        """Ağ analizini çalıştırır"""
        try:
            self.root.after(0, lambda: self.network_summary.config(
                text=f"Ağ analizi çalışıyor: {network_range}"
            ))
            
            def progress_callback(progress, ip, device):
                if not self.scan_running:
                    return
                
                self.root.after(0, lambda: self.network_progress.config(value=progress))
                
                # Cihaz bulunursa hemen ekle
                if device and device.is_alive:
                    self.root.after(0, lambda: self._add_network_device(device))
            
            # Ağ keşfini başlat
            devices = self.network_analyzer.discover_network(network_range, progress_callback)
            
            if self.scan_running:
                self.last_network_results = devices
                topology = self.network_analyzer.analyze_network_topology()
                
                self.root.after(0, lambda: self._update_network_results(devices, topology))
                self.root.after(0, lambda: self._create_network_charts(topology))
                
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Hata", f"Ağ analizi hatası: {str(e)}"))
        finally:
            self.root.after(0, self._network_analysis_finished)
    
    def _add_network_device(self, device):
        """Tek bir ağ cihazını tabloya ekler"""
        ports_str = ', '.join(map(str, device.open_ports[:3]))  # İlk 3 port
        if len(device.open_ports) > 3:
            ports_str += f" (+{len(device.open_ports)-3})"
        
        self.device_tree.insert('', 'end', values=(
            device.ip_address,
            device.hostname,
            device.mac_address,
            device.os_fingerprint,
            device.vendor,
            ports_str,
            f"{device.response_time:.1f}"
        ))
    
    def _update_network_results(self, devices, topology):
        """Ağ analizi sonuçlarını günceller"""
        # Tabloyu temizle
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        # Cihazları ekle
        for device in devices:
            self._add_network_device(device)
        
        # Özet güncelle
        device_count = len(devices)
        self.network_summary.config(text=f"Ağ analizi tamamlandı! {device_count} cihaz bulundu")
    
    def _create_network_charts(self, topology):
        """Ağ topolojisi grafiklerini oluşturur"""
        # Önceki grafikleri temizle
        for widget in self.network_chart_frame.winfo_children():
            widget.destroy()
        
        if not topology['device_types']:
            return
        
        # Matplotlib figure oluştur
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        fig.patch.set_facecolor('#ecf0f1')
        
        # Cihaz türleri pie chart
        ax1.pie(topology['device_types'].values(), 
               labels=topology['device_types'].keys(),
               autopct='%1.1f%%',
               startangle=90)
        ax1.set_title('Cihaz Türleri Dağılımı')
        
        # OS dağılımı bar chart
        if topology['os_distribution']:
            os_names = list(topology['os_distribution'].keys())
            os_counts = list(topology['os_distribution'].values())
            
            ax2.bar(range(len(os_names)), os_counts)
            ax2.set_xticks(range(len(os_names)))
            ax2.set_xticklabels(os_names, rotation=45, ha='right')
            ax2.set_title('İşletim Sistemi Dağılımı')
            ax2.set_ylabel('Cihaz Sayısı')
        
        plt.tight_layout()
        
        # Tkinter canvas'a ekle
        canvas = FigureCanvasTkAgg(fig, self.network_chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)
    
    def _network_analysis_finished(self):
        """Ağ analizi bittiğinde çağrılır"""
        self.scan_running = False
        self.network_scan_btn.config(state='normal')
        self.stop_scan_btn.pack_forget()
        self.network_progress.config(value=100)
        self.status_label.config(text="Ağ analizi tamamlandı")
    
    def stop_scan(self):
        """Çalışan taramayı durdurur"""
        if self.scan_running:
            self.scan_running = False
            self.status_label.config(text="Tarama durduruluyor...")
            
            # Thread'in bitmesini bekle
            if self.current_scan_thread and self.current_scan_thread.is_alive():
                self.current_scan_thread.join(timeout=2)
            
            # UI'yi reset et
            self.port_scan_btn.config(state='normal')
            self.vuln_scan_btn.config(state='normal')
            self.network_scan_btn.config(state='normal')
            self.stop_scan_btn.pack_forget()
            
            self.status_label.config(text="Tarama durduruldu")
    
    def generate_reports(self):
        """Raporları oluşturur"""
        if not any([self.last_port_results, self.last_vuln_results, self.last_network_results]):
            messagebox.showwarning("Uyarı", "Rapor oluşturmak için önce tarama yapın!")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            # JSON raporu
            if self.json_report_var.get():
                self._generate_json_report(timestamp)
            
            # HTML raporu
            if self.html_report_var.get():
                self._generate_html_report(timestamp)
            
            # PDF raporu (placeholder)
            if self.pdf_report_var.get():
                messagebox.showinfo("Bilgi", "PDF raporu özelliği henüz geliştirilmemiştir.")
            
            self.refresh_reports_list()
            messagebox.showinfo("Başarılı", "Raporlar başarıyla oluşturuldu!")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Rapor oluşturma hatası: {str(e)}")
    
    def _generate_json_report(self, timestamp):
        """JSON raporu oluşturur"""
        report_data = {
            'scan_date': datetime.now().isoformat(),
            'port_scan': self.last_port_results,
            'vulnerability_scan': [vars(v) if hasattr(v, '__dict__') else v for v in (self.last_vuln_results or [])],
            'network_analysis': [vars(d) if hasattr(d, '__dict__') else d for d in (self.last_network_results or [])]
        }
        
        filename = f"reports/SecuriPy_Report_{timestamp}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
    
    def _generate_html_report(self, timestamp):
        """HTML raporu oluşturur"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecuriPy Güvenlik Raporu</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                .section {{ background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .critical {{ color: #dc3545; }}
                .high {{ color: #fd7e14; }}
                .medium {{ color: #ffc107; }}
                .low {{ color: #28a745; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
                th, td {{ border: 1px solid #dee2e6; padding: 8px; text-align: left; }}
                th {{ background-color: #e9ecef; }}
                .footer {{ text-align: center; margin-top: 30px; color: #6c757d; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ SecuriPy Güvenlik Analizi Raporu</h1>
                <p>Oluşturulma Tarihi: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
            </div>
        """
        
        # Port tarama sonuçları
        if self.last_port_results:
            html_content += """
            <div class="section">
                <h2>🔍 Port Tarama Sonuçları</h2>
                <table>
                    <tr><th>Port</th><th>Durum</th><th>Servis</th><th>Banner</th></tr>
            """
            for port_num in sorted(self.last_port_results['open_ports']):
                port_info = self.last_port_results['ports'][port_num]
                html_content += f"""
                    <tr>
                        <td>{port_num}</td>
                        <td>{port_info.get('state', 'unknown')}</td>
                        <td>{port_info.get('service', 'unknown')}</td>
                        <td>{port_info.get('banner', '')[:50]}</td>
                    </tr>
                """
            html_content += "</table></div>"
        
        # Güvenlik açığı sonuçları
        if self.last_vuln_results:
            html_content += """
            <div class="section">
                <h2>🔒 Güvenlik Açığı Sonuçları</h2>
                <table>
                    <tr><th>CVE ID</th><th>Başlık</th><th>Severity</th><th>CVSS</th><th>Açıklama</th></tr>
            """
            for vuln in self.last_vuln_results:
                severity_class = vuln.severity.value.lower()
                html_content += f"""
                    <tr>
                        <td>{vuln.cve_id}</td>
                        <td>{vuln.title}</td>
                        <td class="{severity_class}">{vuln.severity.value}</td>
                        <td>{vuln.cvss_score}</td>
                        <td>{vuln.description[:100]}...</td>
                    </tr>
                """
            html_content += "</table></div>"
        
        # Ağ analizi sonuçları
        if self.last_network_results:
            html_content += """
            <div class="section">
                <h2>🌐 Ağ Analizi Sonuçları</h2>
                <table>
                    <tr><th>IP</th><th>Hostname</th><th>OS</th><th>Vendor</th><th>Açık Portlar</th></tr>
            """
            for device in self.last_network_results:
                ports_str = ', '.join(map(str, device.open_ports[:5]))
                html_content += f"""
                    <tr>
                        <td>{device.ip_address}</td>
                        <td>{device.hostname}</td>
                        <td>{device.os_fingerprint}</td>
                        <td>{device.vendor}</td>
                        <td>{ports_str}</td>
                    </tr>
                """
            html_content += "</table></div>"
        
        html_content += """
            <div class="footer">
                <p>Bu rapor SecuriPy Güvenlik Aracı Seti tarafından oluşturulmuştur.</p>
            </div>
        </body>
        </html>
        """
        
        filename = f"reports/SecuriPy_Report_{timestamp}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def refresh_reports_list(self):
        """Raporlar listesini yeniler"""
        self.reports_listbox.delete(0, tk.END)
        
        if os.path.exists('reports'):
            for filename in os.listdir('reports'):
                if filename.endswith(('.json', '.html', '.pdf')):
                    self.reports_listbox.insert(tk.END, filename)
    
    def open_reports_folder(self):
        """Raporlar klasörünü açar"""
        reports_path = os.path.abspath('reports')
        if os.path.exists(reports_path):
            if os.name == 'nt':  # Windows
                os.startfile(reports_path)
            elif os.name == 'posix':  # macOS ve Linux
                subprocess.run(['open' if sys.platform == 'darwin' else 'xdg-open', reports_path])
        else:
            messagebox.showwarning("Uyarı", "Raporlar klasörü bulunamadı!")


def main():
    """Ana uygulama fonksiyonu"""
    root = tk.Tk()
    app = SecuriPyGUI(root)
    
    # Kapanış işlemi
    def on_closing():
        if app.scan_running:
            result = messagebox.askyesno("Çıkış", "Tarama çalışıyor. Yine de çıkmak istiyor musunuz?")
            if result:
                app.stop_scan()
                root.destroy()
        else:
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()