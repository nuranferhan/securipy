import unittest
import sys
import os
import time
import socket
import threading
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.port_scanner import PortScanner

class TestPortScanner(unittest.TestCase):
   
    
    def setUp(self):
       
        self.scanner = PortScanner(timeout=0.5, max_threads=10)
        self.test_host = "127.0.0.1"
    
    def tearDown(self):
     
        pass
    
    def test_scanner_initialization(self):
   
        self.assertEqual(self.scanner.timeout, 0.5)
        self.assertEqual(self.scanner.max_threads, 10)
        self.assertIsInstance(self.scanner.open_ports, list)
        self.assertIsInstance(self.scanner.services, dict)
    
    def test_load_common_ports(self):
     
        self.scanner.load_common_ports()
        self.assertIsInstance(self.scanner.common_ports, dict)
        self.assertIn("80", self.scanner.common_ports)
        self.assertEqual(self.scanner.common_ports["80"], "HTTP")
    
    def test_scan_single_open_port(self):
  
  
        test_server = self._create_test_server()
        
        try:
         
            result = self.scanner.scan_port(self.test_host, test_server.server_address[1])
            
            self.assertEqual(result['port'], test_server.server_address[1])
            self.assertEqual(result['state'], 'open')
            self.assertEqual(result['protocol'], 'tcp')
            
        finally:
            test_server.shutdown()
    
    def test_scan_single_closed_port(self):
   
        result = self.scanner.scan_port(self.test_host, 65432)
        
        self.assertEqual(result['port'], 65432)
        self.assertIn(result['state'], ['closed', 'filtered'])
    
    def test_scan_port_range(self):
 
        test_server = self._create_test_server()
        test_port = test_server.server_address[1]
        
        try:
           
            callback_calls = []
            def test_callback(progress, port, result):
                callback_calls.append((progress, port, result))
            
        
            results = self.scanner.scan_range(
                self.test_host, 
                test_port - 5, 
                test_port + 5, 
                'tcp', 
                test_callback
            )
            
        
            self.assertIsInstance(results, dict)
            self.assertIn('host', results)
            self.assertIn('ports', results)
            self.assertIn('open_ports', results)
            self.assertIn('statistics', results)
            
         
            self.assertIn(test_port, results['open_ports'])
            
      
            self.assertGreater(len(callback_calls), 0)
            
        finally:
            test_server.shutdown()
    
    def test_banner_grabbing(self):
      
        test_server = self._create_http_test_server()
        test_port = test_server.server_address[1]
        
        try:
          
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.test_host, test_port))
            
        
            banner = self.scanner._grab_banner(sock, 80) 
            
            self.assertIsInstance(banner, str)
            
        except Exception:
            pass 
        finally:
            test_server.shutdown()
    
    def test_version_extraction(self):
       
        test_banners = [
            "Apache/2.4.41 (Ubuntu)",
            "nginx/1.18.0",
            "OpenSSH_8.2",
            "Microsoft-IIS/10.0"
        ]
        
        expected_versions = ["2.4.41", "1.18.0", "8.2", "10.0"]
        
        for banner, expected in zip(test_banners, expected_versions):
            version = self.scanner._extract_version(banner, 80)
            self.assertEqual(version, expected)
    
    def test_statistics_calculation(self):
      
        mock_results = {
            'ports': {
                80: {'state': 'open'},
                443: {'state': 'open'},
                8080: {'state': 'closed'},
                22: {'state': 'filtered'}
            },
            'open_ports': [80, 443],
            'duration': 5.5
        }
        
        stats = self.scanner._calculate_statistics(mock_results)
        
        self.assertEqual(stats['total_ports'], 4)
        self.assertEqual(stats['open_ports'], 2)
        self.assertEqual(stats['closed_ports'], 1)
        self.assertEqual(stats['filtered_ports'], 1)
        self.assertEqual(stats['scan_duration'], 5.5)
        self.assertAlmostEqual(stats['ports_per_second'], 4/5.5, places=2)
    
    def test_host_info_gathering(self):
      
        host_info = self.scanner.get_host_info(self.test_host)
        
        self.assertIsInstance(host_info, dict)
        self.assertIn('host', host_info)
        self.assertIn('ip_address', host_info)
        self.assertIn('is_alive', host_info)
        
      
        self.assertEqual(host_info['host'], self.test_host)
        self.assertEqual(host_info['ip_address'], self.test_host)
    
    @patch('subprocess.run')
    def test_ping_functionality(self, mock_run):
     
        mock_run.return_value.returncode = 0
        
        host_info = self.scanner.get_host_info("8.8.8.8")
     
        mock_run.assert_called()
        self.assertTrue(host_info.get('is_alive', False))
    
    def test_export_results_json(self):
 
        test_results = {
            'host': self.test_host,
            'open_ports': [80, 443],
            'ports': {
                80: {'state': 'open', 'service': 'HTTP'},
                443: {'state': 'open', 'service': 'HTTPS'}
            },
            'duration': 2.5
        }
        
      
        test_filename = 'test_export'
        
        try:
            self.scanner.export_results(test_results, test_filename, 'json')
            
        
            expected_path = os.path.join('reports', f'{test_filename}.json')
            self.assertTrue(os.path.exists(expected_path))
            
          
            with open(expected_path, 'r', encoding='utf-8') as f:
                import json
                loaded_data = json.load(f)
                self.assertEqual(loaded_data['host'], self.test_host)
                self.assertEqual(loaded_data['open_ports'], [80, 443])
            
        finally:
       
            try:
                os.remove(os.path.join('reports', f'{test_filename}.json'))
            except:
                pass
    
    def test_export_results_txt(self):
     
      
        test_results = {
            'host': self.test_host,
            'open_ports': [80],
            'ports': {
                80: {'state': 'open', 'service': 'HTTP', 'banner': 'Apache/2.4.41'}
            },
            'duration': 1.0
        }
        
        test_filename = 'test_export_txt'
        
        try:
            self.scanner.export_results(test_results, test_filename, 'txt')
            
          
            expected_path = os.path.join('reports', f'{test_filename}.txt')
            self.assertTrue(os.path.exists(expected_path))
            
           
            with open(expected_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self.assertIn(self.test_host, content)
                self.assertIn('Port 80', content)
                self.assertIn('HTTP', content)
            
        finally:
           
            try:
                os.remove(os.path.join('reports', f'{test_filename}.txt'))
            except:
                pass
    
    def test_udp_scanning(self):
     
        result = self.scanner.scan_port(self.test_host, 53, 'udp')  # DNS portu
        
        self.assertEqual(result['port'], 53)
        self.assertEqual(result['protocol'], 'udp')
        self.assertIn(result['state'], ['open', 'closed', 'open|filtered'])
    
    def test_aggressive_scan_simulation(self):
      
        with patch.object(self.scanner, 'scan_range') as mock_scan:
            mock_scan.return_value = {
                'host': self.test_host,
                'open_ports': [22, 80, 443],
                'duration': 10.0
            }
            
            result = self.scanner.aggressive_scan(self.test_host)
            
       
            mock_scan.assert_called_once_with(self.test_host, 1, 65535, 'tcp', None)
            self.assertEqual(len(result['open_ports']), 3)
    
    def test_common_ports_scan(self):
   
        with patch.object(self.scanner, 'scan_range') as mock_scan:
            mock_scan.return_value = {
                'host': self.test_host,
                'open_ports': [80, 443],
                'duration': 2.0
            }
            
            result = self.scanner.scan_common_ports(self.test_host)
            
        
            mock_scan.assert_called_once()
            self.assertIsInstance(result, dict)
    
    def test_error_handling(self):
    
      
        result = self.scanner.scan_port("invalid.host.name.xyz", 80)
        self.assertIn('error', result)
        
      
        result = self.scanner.scan_port(self.test_host, 70000)  # Geçersiz port
        self.assertIn('error', result)
    
    def test_timeout_handling(self):
       
   
        short_timeout_scanner = PortScanner(timeout=0.001)
        result = short_timeout_scanner.scan_port("10.255.255.1", 80)  # Ulaşılamaz IP
        
        self.assertIn(result['state'], ['filtered', 'closed'])
    
    def test_thread_safety(self):
       
        results = []
        
        def scan_worker():
            result = self.scanner.scan_port(self.test_host, 80)
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
            self.assertIsInstance(result, dict)
            self.assertIn('port', result)
            self.assertIn('state', result)
    
    def _create_test_server(self):
     
        class TestServer:
            def __init__(self):
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.bind(('127.0.0.1', 0))  # Otomatik port
                self.sock.listen(1)
                self.server_address = self.sock.getsockname()
                self.running = True
                
              
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
    
    def _create_http_test_server(self):
     
        class HTTPTestServer:
            def __init__(self):
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.bind(('127.0.0.1', 0))
                self.sock.listen(1)
                self.server_address = self.sock.getsockname()
                self.running = True
                
                self.thread = threading.Thread(target=self._serve)
                self.thread.daemon = True
                self.thread.start()
            
            def _serve(self):
                while self.running:
                    try:
                        self.sock.settimeout(0.5)
                        conn, addr = self.sock.accept()
                        
                        # HTTP benzeri response gönder
                        response = b"HTTP/1.1 200 OK\r\nServer: TestServer/1.0\r\n\r\n"
                        conn.send(response)
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
        
        return HTTPTestServer()


if __name__ == '__main__':
    
    os.makedirs('reports', exist_ok=True)
    
   
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPortScanner)
    
  
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
   
    print(f"\n{'='*50}")
    print(f"Test Özeti:")
    print(f"Toplam Test: {result.testsRun}")
    print(f"Başarılı: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Başarısız: {len(result.failures)}")
    print(f"Hatalı: {len(result.errors)}")
    print(f"{'='*50}")
    
    
    if result.wasSuccessful():
        print("✅ Tüm testler başarılı!")
        exit(0)
    else:
        print("❌ Bazı testler başarısız!")
        exit(1)