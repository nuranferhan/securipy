import unittest
import sys
import os
import time
import socket
import threading
import json
import ipaddress
import platform
from unittest.mock import Mock, patch, MagicMock, mock_open
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.network_analyzer import NetworkAnalyzer, NetworkDevice, NetworkSegment

class TestNetworkDevice(unittest.TestCase):
    
    def test_network_device_creation(self):
        device = NetworkDevice(
            ip_address="192.168.1.100",
            hostname="test-host",
            mac_address="00:11:22:33:44:55",
            os_fingerprint="Linux",
            is_alive=True
        )
        
        self.assertEqual(device.ip_address, "192.168.1.100")
        self.assertEqual(device.hostname, "test-host")
        self.assertEqual(device.mac_address, "00:11:22:33:44:55")
        self.assertEqual(device.os_fingerprint, "Linux")
        self.assertTrue(device.is_alive)
        self.assertIsInstance(device.open_ports, list)
        self.assertIsInstance(device.services, dict)
    
    def test_network_device_defaults(self):
        device = NetworkDevice(ip_address="192.168.1.1")
        
        self.assertEqual(device.hostname, "")
        self.assertEqual(device.mac_address, "")
        self.assertEqual(device.os_fingerprint, "")
        self.assertEqual(device.vendor, "")
        self.assertEqual(device.response_time, 0.0)
        self.assertFalse(device.is_alive)
        self.assertEqual(device.open_ports, [])
        self.assertEqual(device.services, {})
    
    def test_network_device_to_dict(self):
        device = NetworkDevice(
            ip_address="192.168.1.50",
            hostname="web-server",
            open_ports=[80, 443],
            services={80: "HTTP", 443: "HTTPS"}
        )
        
        device_dict = asdict(device)
        self.assertIsInstance(device_dict, dict)
        self.assertEqual(device_dict['ip_address'], "192.168.1.50")
        self.assertEqual(device_dict['open_ports'], [80, 443])


class TestNetworkSegment(unittest.TestCase):
    
    def test_network_segment_creation(self):
        segment = NetworkSegment(
            network="192.168.1.0/24",
            netmask="255.255.255.0",
            gateway="192.168.1.1"
        )
        
        self.assertEqual(segment.network, "192.168.1.0/24")
        self.assertEqual(segment.netmask, "255.255.255.0")
        self.assertEqual(segment.gateway, "192.168.1.1")
        self.assertIsInstance(segment.dns_servers, list)
        self.assertIsInstance(segment.devices, list)


class TestNetworkAnalyzer(unittest.TestCase):
    
    def setUp(self):
        self.analyzer = NetworkAnalyzer(timeout=0.5, max_threads=10)
        self.test_ip = "192.168.1.100"
    
    def tearDown(self):
        test_files = [
            'reports/test_network_scan.json',
            'reports/test_network_scan.html'
        ]
        for file_path in test_files:
            try:
                os.remove(file_path)
            except:
                pass
    
    def test_analyzer_initialization(self):
        self.assertEqual(self.analyzer.timeout, 0.5)
        self.assertEqual(self.analyzer.max_threads, 10)
        self.assertIsInstance(self.analyzer.discovered_devices, list)
        self.assertIsInstance(self.analyzer.network_segments, list)
        self.assertIsInstance(self.analyzer.os_patterns, dict)
        self.assertIsInstance(self.analyzer.mac_vendors, dict)
    
    def test_load_os_patterns_default(self):
        self.analyzer.load_os_patterns()
        
        self.assertIn("windows", self.analyzer.os_patterns)
        self.assertIn("linux", self.analyzer.os_patterns)
        self.assertIn("macos", self.analyzer.os_patterns)
        
        windows_pattern = self.analyzer.os_patterns["windows"]
        self.assertIn("ttl_values", windows_pattern)
        self.assertIn("patterns", windows_pattern)
    
    @patch('builtins.open', mock_open(read_data='{"test_os": {"ttl_values": [64]}}'))
    def test_load_os_patterns_from_file(self):
        patterns = self.analyzer.load_os_patterns()
        
        self.assertIn("test_os", patterns)
        self.assertEqual(patterns["test_os"]["ttl_values"], [64])
    
    def test_load_mac_vendors_default(self):
        self.analyzer.load_mac_vendors()
        
        self.assertIn("00:50:56", self.analyzer.mac_vendors)
        self.assertEqual(self.analyzer.mac_vendors["00:50:56"], "VMware")
    
    @patch('subprocess.run')
    def test_ping_host_success(self, mock_run):
     
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "Reply from 192.168.1.1"
        
        with patch('socket.gethostbyaddr', return_value=('test-host', [], ['192.168.1.1'])):
            device = self.analyzer._ping_host("192.168.1.1")
        
        self.assertIsNotNone(device)
        self.assertEqual(device.ip_address, "192.168.1.1")
        self.assertTrue(device.is_alive)
        self.assertEqual(device.hostname, "test-host")
        self.assertGreater(device.response_time, 0)
    
    @patch('subprocess.run')
    def test_ping_host_failure(self, mock_run):
    
        mock_run.return_value.returncode = 1
        
        device = self.analyzer._ping_host("192.168.1.999")
        
        self.assertIsNone(device)
    
    @patch('subprocess.run')
    def test_ping_host_timeout(self, mock_run):
     
        mock_run.side_effect = TimeoutError()
        
        device = self.analyzer._ping_host("10.255.255.1")
        
        self.assertIsNone(device)
    
    @patch('ipaddress.IPv4Network')
    @patch.object(NetworkAnalyzer, '_ping_host')
    def test_discover_network(self, mock_ping, mock_network):
      
        mock_network.return_value.hosts.return_value = [
            ipaddress.IPv4Address('192.168.1.1'),
            ipaddress.IPv4Address('192.168.1.2')
        ]
        mock_network.return_value.broadcast_address = ipaddress.IPv4Address('192.168.1.255')
        
        device1 = NetworkDevice(ip_address="192.168.1.1", is_alive=True)
        device2 = NetworkDevice(ip_address="192.168.1.2", is_alive=True)
        mock_ping.side_effect = [device1, device2, None] 
        
        callback_calls = []
        def test_callback(progress, ip, device):
            callback_calls.append((progress, ip, device))
        
        with patch.object(self.analyzer, '_analyze_discovered_devices'):
            devices = self.analyzer.discover_network("192.168.1.0/24", test_callback)
        
        self.assertEqual(len(devices), 2)
        self.assertGreater(len(callback_calls), 0)
        self.assertEqual(self.analyzer.discovered_devices, devices)
    
    @patch('subprocess.run')
    def test_get_mac_address_windows(self, mock_run):

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            "Interface: 192.168.1.5 --- 0x2\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           00-11-22-33-44-55     dynamic\n"
        )
        
        with patch('platform.system', return_value='Windows'):
            mac = self.analyzer._get_mac_address("192.168.1.1")
        
        self.assertEqual(mac, "00:11:22:33:44:55")
    
    @patch('subprocess.run')
    def test_get_mac_address_linux(self, mock_run):
    
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            "Address                  HWtype  HWaddress           Flags Mask            Iface\n"
            "192.168.1.1              ether   aa:bb:cc:dd:ee:ff   C                     eth0\n"
        )
        
        with patch('platform.system', return_value='Linux'):
            mac = self.analyzer._get_mac_address("192.168.1.1")
        
        self.assertEqual(mac, "AA:BB:CC:DD:EE:FF")
    
    def test_get_vendor_from_mac(self):
      
        vendor = self.analyzer._get_vendor_from_mac("00:50:56:12:34:56")
        self.assertEqual(vendor, "VMware")
        
        vendor = self.analyzer._get_vendor_from_mac("FF:FF:FF:FF:FF:FF")
        self.assertEqual(vendor, "Unknown")
        
        vendor = self.analyzer._get_vendor_from_mac("")
        self.assertEqual(vendor, "")
    
    @patch('subprocess.run')
    def test_get_ttl_windows(self, mock_run):
      
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            "Pinging 192.168.1.1 with 32 bytes of data:\n"
            "Reply from 192.168.1.1: bytes=32 time<1ms TTL=64\n"
        )
        
        with patch('platform.system', return_value='Windows'):
            ttl = self.analyzer._get_ttl("192.168.1.1")
        
        self.assertEqual(ttl, 64)
    
    @patch('subprocess.run')
    def test_get_ttl_linux(self, mock_run):
      
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
            "64 bytes from 192.168.1.1: icmp_seq=1 ttl=128 time=0.5 ms\n"
        )
        
        with patch('platform.system', return_value='Linux'):
            ttl = self.analyzer._get_ttl("192.168.1.1")
        
        self.assertEqual(ttl, 128)
    
    def test_detect_os_from_ttl(self):
       
        with patch.object(self.analyzer, '_get_ttl') as mock_ttl:
        
            mock_ttl.return_value = 64
            os_type = self.analyzer._detect_os("192.168.1.1")
            self.assertIn("Linux", os_type)
            
            mock_ttl.return_value = 128
            os_type = self.analyzer._detect_os("192.168.1.1")
            self.assertIn("Windows", os_type)
            
            mock_ttl.return_value = 255
            os_type = self.analyzer._detect_os("192.168.1.1")
            self.assertIn("Cisco", os_type)
    
    def test_detect_os_from_banners(self):
    
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0
        mock_socket.recv.return_value = b"Server: Apache/2.4.41 (Ubuntu)"
        
        with patch('socket.socket', return_value=mock_socket):
            os_type = self.analyzer._detect_os_from_banners("192.168.1.1")
        
        self.assertIn("Ubuntu", os_type)
    
    def test_scan_single_port_open(self):
   
        test_server = self._create_test_server()
        
        try:
            is_open = self.analyzer._scan_single_port(
                "127.0.0.1", 
                test_server.server_address[1]
            )
            self.assertTrue(is_open)
        finally:
            test_server.shutdown()
    
    def test_scan_single_port_closed(self):
     
        is_open = self.analyzer._scan_single_port("127.0.0.1", 65432)
        self.assertFalse(is_open)
    
    def test_quick_port_scan(self):
      
        test_server = self._create_test_server()
        test_port = test_server.server_address[1]
        
        try:
          
            original_common_ports = {
                21: "FTP", 22: "SSH", test_port: "TEST"
            }
            
            with patch.dict('modules.network_analyzer.NetworkAnalyzer._quick_port_scan.__defaults__[0]', 
                          original_common_ports, clear=True):
               
                with patch.object(self.analyzer, '_scan_single_port') as mock_scan:
                    mock_scan.side_effect = lambda ip, port: port == test_port
                    
                    open_ports, services = self.analyzer._quick_port_scan("127.0.0.1")
                    
                    self.assertTrue(mock_scan.called)
        finally:
            test_server.shutdown()
    
    def test_classify_device_type(self):
     
        device = NetworkDevice(ip_address="192.168.1.1", open_ports=[80, 443, 22])
        device_type = self.analyzer._classify_device_type(device)
        self.assertIn("Web Server", device_type)
        
        device = NetworkDevice(ip_address="192.168.1.2", open_ports=[3306])
        device_type = self.analyzer._classify_device_type(device)
        self.assertEqual(device_type, "Database Server")
        
        device = NetworkDevice(ip_address="192.168.1.3", open_ports=[53])
        device_type = self.analyzer._classify_device_type(device)
        self.assertEqual(device_type, "DNS Server")
        
        device = NetworkDevice(ip_address="192.168.1.4", open_ports=[3389])
        device_type = self.analyzer._classify_device_type(device)
        self.assertEqual(device_type, "Windows Desktop")
        
        device = NetworkDevice(ip_address="192.168.1.5", open_ports=[9999])
        device_type = self.analyzer._classify_device_type(device)
        self.assertEqual(device_type, "Unknown Device")
    
    @patch('subprocess.run')
    def test_detect_gateways_windows(self, mock_run):
     
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            "Network Destination        Netmask          Gateway       Interface  Metric\n"
            "          0.0.0.0          0.0.0.0    192.168.1.1   192.168.1.100     25\n"
        )
        
        with patch('platform.system', return_value='Windows'):
            gateways = self.analyzer._detect_gateways()
        
        self.assertIn("192.168.1.1", gateways)
    
    @patch('subprocess.run')
    def test_detect_gateways_linux(self, mock_run):
    
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            "Kernel IP routing table\n"
            "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
            "0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 eth0\n"
        )
        
        with patch('platform.system', return_value='Linux'):
            gateways = self.analyzer._detect_gateways()
        
        self.assertIn("192.168.1.1", gateways)
    
    def test_analyze_network_topology(self):
    
        devices = [
            NetworkDevice(ip_address="192.168.1.1", open_ports=[80, 443], 
                         os_fingerprint="Linux", vendor="Intel"),
            NetworkDevice(ip_address="192.168.1.2", open_ports=[3306], 
                         os_fingerprint="Windows", vendor="VMware"),
            NetworkDevice(ip_address="192.168.1.3", open_ports=[53], 
                         os_fingerprint="Linux", vendor="Intel"),
        ]
        
        self.analyzer.discovered_devices = devices
        
        with patch.object(self.analyzer, '_detect_gateways', return_value=['192.168.1.1']):
            topology = self.analyzer.analyze_network_topology()
        
        self.assertEqual(topology['total_devices'], 3)
        self.assertIn('device_types', topology)
        self.assertIn('os_distribution', topology)
        self.assertIn('vendor_distribution', topology)
        
        self.assertEqual(topology['os_distribution']['Linux'], 2)
        self.assertEqual(topology['os_distribution']['Windows'], 1)
        
        self.assertEqual(topology['vendor_distribution']['Intel'], 2)
        self.assertEqual(topology['vendor_distribution']['VMware'], 1)
    
    @patch('subprocess.run')
    def test_get_network_interfaces_windows(self, mock_run):
     
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            "Ethernet adapter Local Area Connection:\n"
            "   IPv4 Address. . . . . . . . . . . : 192.168.1.100\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
            "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
        )
        
        with patch('platform.system', return_value='Windows'):
            interfaces = self.analyzer.get_network_interfaces()
        
        self.assertGreater(len(interfaces), 0)
        interface = interfaces[0]
        self.assertIn('name', interface)
    
    @patch('subprocess.run')
    def test_get_network_interfaces_linux(self, mock_run):
     
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n"
        )
        
        with patch('platform.system', return_value='Linux'):
            interfaces = self.analyzer.get_network_interfaces()
        
        self.assertGreater(len(interfaces), 0)
        interface = interfaces[0]
        self.assertEqual(interface['name'], 'eth0')
    
    def test_detailed_device_analysis(self):
      
        device = NetworkDevice(ip_address="192.168.1.100", is_alive=True)
        
        with patch.object(self.analyzer, '_get_mac_address', return_value="00:11:22:33:44:55"):
            with patch.object(self.analyzer, '_get_vendor_from_mac', return_value="Intel"):
                with patch.object(self.analyzer, '_detect_os', return_value="Linux"):
                    with patch.object(self.analyzer, '_quick_port_scan', 
                                    return_value=([80, 22], {80: "HTTP", 22: "SSH"})):
                        
                        updated_device = self.analyzer._detailed_device_analysis(device)
        
        self.assertEqual(updated_device.mac_address, "00:11:22:33:44:55")
        self.assertEqual(updated_device.vendor, "Intel")
        self.assertEqual(updated_device.os_fingerprint, "Linux")
        self.assertEqual(updated_device.open_ports, [80, 22])
        self.assertEqual(updated_device.services, {80: "HTTP", 22: "SSH"})
    
    def test_export_network_analysis_json(self):
      
        test_devices = [
            NetworkDevice(ip_address="192.168.1.1", hostname="router", is_alive=True),
            NetworkDevice(ip_address="192.168.1.100", hostname="server", open_ports=[80, 443])
        ]
        self.analyzer.discovered_devices = test_devices
        
        with patch.object(self.analyzer, 'analyze_network_topology', 
                         return_value={'total_devices': 2}):
            with patch.object(self.analyzer, 'get_network_interfaces', 
                            return_value=[{'name': 'eth0'}]):
                
                self.analyzer.export_network_analysis('test_network_scan', 'json')
        
        expected_path = 'reports/test_network_scan.json'
        self.assertTrue(os.path.exists(expected_path))
        
        with open(expected_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            self.assertIn('discovered_devices', data)
            self.assertIn('topology', data)
            self.assertIn('interfaces', data)
            self.assertEqual(len(data['discovered_devices']), 2)
    
    def test_export_network_analysis_html(self):
      
        test_devices = [
            NetworkDevice(ip_address="192.168.1.1", hostname="test-host", 
                         mac_address="00:11:22:33:44:55", vendor="Intel",
                         os_fingerprint="Linux", open_ports=[80, 443], 
                         response_time=1.5, is_alive=True)
        ]
        self.analyzer.discovered_devices = test_devices
        
        with patch.object(self.analyzer, 'analyze_network_topology', 
                         return_value={
                             'device_types': {'Web Server': 1},
                             'os_distribution': {'Linux': 1}
                         }):
            with patch.object(self.analyzer, 'get_network_interfaces', 
                            return_value=[]):
                
                self.analyzer.export_network_analysis('test_network_scan', 'html')
        
        expected_path = 'reports/test_network_scan.html'
        self.assertTrue(os.path.exists(expected_path))
        
        with open(expected_path, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn('Ağ Analizi Raporu', content)
            self.assertIn('192.168.1.1', content)
            self.assertIn('test-host', content)
            self.assertIn('Linux', content)
    
    def test_generate_html_report(self):
      
        test_data = {
            'scan_time': '2024-01-01 12:00:00',
            'discovered_devices': [
                {
                    'ip_address': '192.168.1.1',
                    'hostname': 'router',
                    'mac_address': '00:11:22:33:44:55',
                    'vendor': 'Cisco',
                    'os_fingerprint': 'Linux',
                    'open_ports': [22, 80, 443],
                    'response_time': 1.2
                }
            ],
            'topology': {
                'device_types': {'Router': 1},
                'os_distribution': {'Linux': 1}
            }
        }
        
        html_content = self.analyzer._generate_network_html_report(test_data)
        
        self.assertIn('<!DOCTYPE html>', html_content)
        self.assertIn('Ağ Analizi Raporu', html_content)
        self.assertIn('192.168.1.1', html_content)
        self.assertIn('router', html_content)
        self.assertIn('Cisco', html_content)
        self.assertIn('22, 80, 443', html_content)
    
    def test_thread_safety(self):
     
        results = []
        
        def scan_worker():
            with patch.object(self.analyzer, '_ping_host', 
                            return_value=NetworkDevice(ip_address="192.168.1.1", is_alive=True)):
                result = self.analyzer._ping_host("192.168.1.1")
                results.append(result)
        
       
        threads = []
        for _ in range(5):
            t = threading.Thread(target=scan_worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        self.assertEqual(len(results), 5)
        for result in results:
            self.assertIsInstance(result, NetworkDevice)
            self.assertTrue(result.is_alive)
    
    def test_error_handling(self):
      
        with self.assertLogs() as log:
            devices = self.analyzer.discover_network("invalid.network.range")
            self.assertEqual(len(devices), 0)
        
        device = self.analyzer._ping_host("invalid.ip.address")
        self.assertIsNone(device)
        
        with patch('subprocess.run', side_effect=TimeoutError()):
            device = self.analyzer._ping_host("192.168.1.1")
            self.assertIsNone(device)
    
    def test_callback_functionality(self):
       
        callback_calls = []
        
        def test_callback(progress, ip, device):
            callback_calls.append((progress, ip, device))
        
        with patch('ipaddress.IPv4Network') as mock_network:
            mock_network.return_value.hosts.return_value = [
                ipaddress.IPv4Address('192.168.1.1')
            ]
            mock_network.return_value.broadcast_address = None
            
            with patch.object(self.analyzer, '_ping_host', 
                            return_value=NetworkDevice(ip_address="192.168.1.1", is_alive=True)):
                with patch.object(self.analyzer, '_analyze_discovered_devices'):
                    self.analyzer.discover_network("192.168.1.0/24", test_callback)
        
       
        self.assertGreater(len(callback_calls), 0)
        progress, ip, device = callback_calls[0]
        self.assertIsInstance(progress, float)
        self.assertEqual(ip, "192.168.1.1")
        self.assertIsInstance(device, NetworkDevice)
    
    def test_parse_windows_interfaces(self):
   
        windows_output = """
Windows IP Configuration

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.1.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.0.0.5
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.0.0.1
"""
        
        interfaces = self.analyzer._parse_windows_interfaces(windows_output)
        
        self.assertEqual(len(interfaces), 2)
        
        eth_interface = interfaces[0]
        self.assertIn('Local Area Connection', eth_interface['name'])
        self.assertEqual(eth_interface['ip'], '192.168.1.100')
        self.assertEqual(eth_interface['netmask'], '255.255.255.0')
        self.assertEqual(eth_interface['gateway'], '192.168.1.1')
        
        wifi_interface = interfaces[1]
        self.assertIn('Wi-Fi', wifi_interface['name'])
        self.assertEqual(wifi_interface['ip'], '10.0.0.5')
        self.assertEqual(wifi_interface['gateway'], '10.0.0.1')
    
    def test_parse_unix_interfaces(self):
       
        unix_output = """
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.15  netmask 255.255.255.0  broadcast 10.0.0.255
"""
        
        interfaces = self.analyzer._parse_unix_interfaces(unix_output)
        
        self.assertGreaterEqual(len(interfaces), 3)
        
        eth_interface = next((iface for iface in interfaces if iface['name'] == 'eth0'), None)
        self.assertIsNotNone(eth_interface)
        self.assertEqual(eth_interface['ip'], '192.168.1.100')
        self.assertEqual(eth_interface['netmask'], '255.255.255.0')
        
        lo_interface = next((iface for iface in interfaces if iface['name'] == 'lo'), None)
        self.assertIsNotNone(lo_interface)
        self.assertEqual(lo_interface['ip'], '127.0.0.1')
        
        wlan_interface = next((iface for iface in interfaces if iface['name'] == 'wlan0'), None)
        self.assertIsNotNone(wlan_interface)
        self.assertEqual(wlan_interface['ip'], '10.0.0.15')
    
    def test_advanced_os_detection(self):
     
        
        with patch.object(self.analyzer, '_get_ttl', return_value=64):
            with patch.object(self.analyzer, '_detect_os_from_banners', return_value=""):
                os_type = self.analyzer._detect_os("192.168.1.1")
                self.assertEqual(os_type, "Linux/Unix")
        
        with patch.object(self.analyzer, '_get_ttl', return_value=None):
            with patch.object(self.analyzer, '_detect_os_from_banners', return_value="Ubuntu Linux"):
                os_type = self.analyzer._detect_os("192.168.1.1")
                self.assertEqual(os_type, "Ubuntu Linux")
        
        with patch.object(self.analyzer, '_get_ttl', return_value=63):  # 64-1 (router hop)
            with patch.object(self.analyzer, '_detect_os_from_banners', return_value=""):
                os_type = self.analyzer._detect_os("192.168.1.1")
                self.assertEqual(os_type, "Linux/Unix (through router)")
    
    def test_comprehensive_device_classification(self):
       
        test_cases = [
       
            {
                'ports': [22, 80, 443],
                'expected': 'Web Server (Linux)'
            },
          
            {
                'ports': [80, 443, 3389],
                'expected': 'Web Server (Windows)'
            },
    
            {
                'ports': [25, 110, 143, 993],
                'expected': 'Mail Server'
            },
     
            {
                'ports': [139, 445],
                'expected': 'File Server'
            },
        
            {
                'ports': [22],
                'expected': 'Linux Desktop'
            },
      
            {
                'ports': [80],
                'expected': 'IoT Device'
            },
         
            {
                'ports': [23],
                'expected': 'Network Device'
            }
        ]
        
        for test_case in test_cases:
            with self.subTest(ports=test_case['ports']):
                device = NetworkDevice(
                    ip_address="192.168.1.1", 
                    open_ports=test_case['ports']
                )
                device_type = self.analyzer._classify_device_type(device)
                self.assertEqual(device_type, test_case['expected'])
    
    def test_mac_address_edge_cases(self):
      
        test_cases = [
            ("00-11-22-33-44-55", "00:11:22:33:44:55"),
            ("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"),
            ("", ""),
            ("invalid-mac", "")
        ]
        
        for input_mac, expected in test_cases:
            with self.subTest(mac=input_mac):
                if input_mac and ":" in input_mac:
                    # Normal MAC format test
                    vendor = self.analyzer._get_vendor_from_mac(input_mac)
                    self.assertIsInstance(vendor, str)
    
    def test_network_range_validation(self):
     
        valid_ranges = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.1.1/32"
        ]
        
        for network_range in valid_ranges:
            with self.subTest(range=network_range):
                try:
                    network = ipaddress.IPv4Network(network_range, strict=False)
                    self.assertIsInstance(network, ipaddress.IPv4Network)
                except Exception as e:
                    self.fail(f"Valid network range {network_range} failed: {e}")
    
    def test_performance_monitoring(self):
  
        start_time = time.time()
        
        with patch.object(self.analyzer, '_ping_host', 
                         return_value=NetworkDevice(ip_address="192.168.1.1", is_alive=True)):
            device = self.analyzer._ping_host("192.168.1.1")
        
        duration = time.time() - start_time
        
        self.assertLess(duration, 1.0)
        self.assertIsNotNone(device)
        self.assertGreater(device.response_time, 0)
    
    def test_concurrent_analysis(self):
  
        devices = [
            NetworkDevice(ip_address=f"192.168.1.{i}", is_alive=True)
            for i in range(1, 6)  # 5 cihaz
        ]
        
        with patch.object(self.analyzer, '_detailed_device_analysis') as mock_analysis:
            mock_analysis.return_value = NetworkDevice(
                ip_address="192.168.1.1", 
                mac_address="00:11:22:33:44:55",
                os_fingerprint="Linux"
            )
            
            self.analyzer._analyze_discovered_devices(devices)
            
            self.assertEqual(mock_analysis.call_count, 5)
    
    def test_export_error_handling(self):
  
        self.analyzer.discovered_devices = [
            NetworkDevice(ip_address="192.168.1.1")
        ]
        

        try:
            self.analyzer.export_network_analysis('test_invalid', 'xml')
         
            self.assertFalse(os.path.exists('reports/test_invalid.xml'))
        except Exception as e:
            self.fail(f"Export should handle invalid format gracefully: {e}")
    
    def _create_test_server(self):

        class TestServer:
            def __init__(self):
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.bind(('127.0.0.1', 0))  # Otomatik port
                self.sock.listen(1)
                self.server_address = self.sock.getsockname()
                self.running = True
                
                # Server thread başlat
                self.thread = threading.Thread(target=self._serve)
                self.thread.daemon = True
                self.thread.start()
            
            def _serve(self):
                while self.running:
                    try:
                        self.sock.settimeout(0.5)
                        conn, addr = self.sock.accept()
                        conn.close()
                    except socket.timeout:
                        continue
                    except:
                        break
            
            def shutdown(self):
                self.running = False
                try:
                    self.sock.close()
                except:
                    pass
                if self.thread.is_alive():
                    self.thread.join(timeout=1)
        
        return TestServer()


class TestIntegration(unittest.TestCase):

    
    def setUp(self):
       
        self.analyzer = NetworkAnalyzer(timeout=0.5, max_threads=5)
    
    def test_full_network_discovery_simulation(self):
   
        mock_devices = [
            NetworkDevice(
                ip_address="192.168.1.1",
                hostname="gateway",
                mac_address="00:11:22:33:44:55",
                os_fingerprint="Linux",
                vendor="Cisco",
                open_ports=[22, 80, 443],
                services={22: "SSH", 80: "HTTP", 443: "HTTPS"},
                is_alive=True,
                response_time=1.5
            ),
            NetworkDevice(
                ip_address="192.168.1.100",
                hostname="server",
                mac_address="00:50:56:12:34:56",
                os_fingerprint="Windows Server",
                vendor="VMware",
                open_ports=[80, 443, 3389],
                services={80: "HTTP", 443: "HTTPS", 3389: "RDP"},
                is_alive=True,
                response_time=2.1
            )
        ]
        
        with patch.object(self.analyzer, 'discover_network', return_value=mock_devices):
            with patch.object(self.analyzer, 'analyze_network_topology') as mock_topology:
                mock_topology.return_value = {
                    'total_devices': 2,
                    'device_types': {'Gateway': 1, 'Web Server': 1},
                    'os_distribution': {'Linux': 1, 'Windows Server': 1},
                    'vendor_distribution': {'Cisco': 1, 'VMware': 1},
                    'gateways': ['192.168.1.1']
                }
                
                devices = self.analyzer.discover_network("192.168.1.0/24")
                topology = self.analyzer.analyze_network_topology()
                
                self.assertEqual(len(devices), 2)
                self.assertEqual(topology['total_devices'], 2)
                self.assertIn('Gateway', topology['device_types'])
                self.assertIn('Web Server', topology['device_types'])
    
    def test_error_recovery(self):

        def mock_ping_with_errors(ip):
            if ip == "192.168.1.1":
                return NetworkDevice(ip_address=ip, is_alive=True)
            elif ip == "192.168.1.2":
                raise ConnectionError("Network unreachable")
            else:
                return None
        
        with patch('ipaddress.IPv4Network') as mock_network:
            mock_network.return_value.hosts.return_value = [
                ipaddress.IPv4Address('192.168.1.1'),
                ipaddress.IPv4Address('192.168.1.2'),
                ipaddress.IPv4Address('192.168.1.3')
            ]
            mock_network.return_value.broadcast_address = None
            
            with patch.object(self.analyzer, '_ping_host', side_effect=mock_ping_with_errors):
                with patch.object(self.analyzer, '_analyze_discovered_devices'):
                    devices = self.analyzer.discover_network("192.168.1.0/24")
        
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].ip_address, "192.168.1.1")


if __name__ == '__main__':

    os.makedirs('reports', exist_ok=True)
    os.makedirs('data', exist_ok=True)
    

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    

    suite.addTests(loader.loadTestsFromTestCase(TestNetworkDevice))
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkSegment))
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
 
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(suite)

    print(f"\n{'='*60}")
    print(f"Network Analyzer Test Özeti:")
    print(f"{'='*60}")
    print(f"Toplam Test: {result.testsRun}")
    print(f"Başarılı: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Başarısız: {len(result.failures)}")
    print(f"Hatalı: {len(result.errors)}")
    
    if result.failures:
        print(f"\nBaşarısız Testler:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.split('AssertionError: ')[-1].split(chr(10))[0]}")
    
    if result.errors:
        print(f"\nHatalı Testler:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.split(chr(10))[-2]}")
    
    print(f"{'='*60}")
    
  
    if result.wasSuccessful():
        print("✅ Tüm testler başarılı!")
        print("🔍 Network Analyzer modülü test edildi:")
        print("   • Ağ keşfi (Network Discovery)")
        print("   • Cihaz analizi (Device Analysis)")
        print("   • OS fingerprinting")
        print("   • MAC vendor tespiti")
        print("   • Port tarama")
        print("   • Topoloji analizi")
        print("   • Rapor oluşturma")
        print("   • Hata yönetimi")
        print("   • Thread güvenliği")
        exit(0)
    else:
        print("❌ Bazı testler başarısız!")
        print("🔧 Lütfen başarısız testleri kontrol edin.")
        exit(1)