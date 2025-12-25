import unittest
from unittest.mock import MagicMock, patch
from agent.process import ProcessTracker

class TestProcessTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = ProcessTracker()

    @patch('psutil.net_connections')
    @patch('psutil.Process')
    def test_get_process_info_found(self, mock_process_cls, mock_net_connections):
        # 1. Setup Mock Connections
        # Simulate a connection: Local 1234 -> Remote 8.8.8.8:443
        mock_conn = MagicMock()
        mock_conn.status = 'ESTABLISHED'
        mock_conn.laddr.port = 1234
        mock_conn.raddr.ip = '8.8.8.8'
        mock_conn.raddr.port = 443
        mock_conn.pid = 9999
        
        mock_net_connections.return_value = [mock_conn]

        # 2. Setup Mock Process Details for PID 9999
        mock_proc_instance = MagicMock()
        mock_proc_instance.exe.return_value = "C:\\Windows\\System32\\test_app.exe"
        mock_proc_instance.name.return_value = "test_app.exe"
        mock_proc_instance.username.return_value = "AUTHORITY\\SYSTEM"
        mock_process_cls.return_value = mock_proc_instance

        # 3. Refresh Cache (triggering net_connections)
        self.tracker.refresh_cache()

        # 4. Query for the known connection
        # Arguments: remote_ip, remote_port, local_port
        info = self.tracker.get_process_info('8.8.8.8', 443, 1234)

        # 5. Assertions
        self.assertIsNotNone(info)
        self.assertEqual(info['path'], "C:\\Windows\\System32\\test_app.exe")
        self.assertEqual(info['user_context'], "AUTHORITY\\SYSTEM")

    @patch('psutil.net_connections')
    def test_get_process_info_not_found(self, mock_net_connections):
        # Setup empty connections
        mock_net_connections.return_value = []
        self.tracker.refresh_cache()

        # Query for non-existent connection
        info = self.tracker.get_process_info('1.2.3.4', 80, 5555)
        self.assertIsNone(info)

if __name__ == '__main__':
    unittest.main()
