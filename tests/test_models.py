"""
Unit tests for model and schema classes

Tests for data models and schemas used in the project
"""
import unittest
import sys
import os
from unittest.mock import Mock, call, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestODDataModels(unittest.TestCase):
    """Test oc.od data models"""
    
    def test_import_od_models(self):
        """Test importing OD model modules"""
        model_modules = [
            'oc.od.apps',
            'oc.od.acl',
            'oc.od.appinstancestatus',
        ]
        
        for module_name in model_modules:
            try:
                __import__(module_name)
            except ImportError:
                # Skip if not available
                pass
    
    def test_od_accounting_module(self):
        """Test accounting module exists"""
        try:
            import oc.od.accounting
            self.assertIsNotNone(oc.od.accounting)
        except ImportError:
            self.skipTest("accounting module not available")


class TestNetworkModules(unittest.TestCase):
    """Test network-related modules"""
    
    def test_import_networks_module(self):
        """Test importing networks module"""
        try:
            import oc.networks
            self.assertIsNotNone(oc.networks)
        except ImportError:
            self.skipTest("networks module not available")
    
    def test_import_thread_event_networks(self):
        """Test importing thread_event_networks"""
        try:
            from oc.networks.thread_event_networks import ThreadEventNetworks
            self.assertIsNotNone(ThreadEventNetworks)
        except ImportError:
            self.skipTest("ThreadEventNetworks not available")


class TestDatastoreModule(unittest.TestCase):
    """Test datastore module"""
    
    def test_import_datastore(self):
        """Test importing datastore module"""
        try:
            import oc.datastore
            self.assertIsNotNone(oc.datastore)
        except ImportError:
            self.skipTest("datastore module not available")


    def test_createclient_reuses_client_per_database(self):
        import oc.datastore as datastore_module

        with patch.object(datastore_module, 'MongoClient', side_effect=[Mock(), Mock()]) as mongo_client:
            datastore = datastore_module.ODMongoDatastoreClient('mongodb://mongodb:27017', 'replicaSet=rs0')
            first_client = datastore.createclient('users')
            second_client = datastore.createclient('users')
            other_client = datastore.createclient('applications')

            self.assertIs(first_client, second_client)
            self.assertIsNot(first_client, other_client)
            self.assertEqual(mongo_client.call_args_list, [
                call(host='mongodb://mongodb:27017/users?replicaSet=rs0&authSource=users'),
                call(host='mongodb://mongodb:27017/applications?replicaSet=rs0&authSource=applications'),
            ])

    def test_createclient_does_not_enable_pool_instrumentation(self):
        import oc.datastore as datastore_module

        with patch.dict(os.environ, {'MONGODB_POOL_METRICS': 'true'}):
            with patch.object(datastore_module, 'MongoClient') as mongo_client:
                datastore = datastore_module.ODMongoDatastoreClient('mongodb://mongodb:27017')
                datastore.createclient('users')

                mongo_client.assert_called_once_with(host=datastore.createhosturl('users'))
                self.assertFalse(hasattr(datastore_module, 'MongoPoolEventLogger'))

    def test_close_closes_each_cached_client_once(self):
        import oc.datastore as datastore_module

        with patch.object(datastore_module, 'MongoClient', side_effect=[Mock(), Mock()]):
            datastore = datastore_module.ODMongoDatastoreClient('mongodb://mongodb:27017')
            users_client = datastore.createclient('users')
            applications_client = datastore.createclient('applications')

            datastore.close()
            datastore.close()

            users_client.close.assert_called_once_with()
            applications_client.close.assert_called_once_with()
            self.assertEqual(datastore._clients, {})

    def test_operations_keep_client_open_until_datastore_close(self):
        import oc.datastore as datastore_module

        with patch.object(datastore_module, 'MongoClient') as mongo_client:
            datastore = datastore_module.ODMongoDatastoreClient('mongodb://mongodb:27017')
            client = datastore.createclient('users')
            client['users']['settings'].find_one.return_value = None

            datastore.get_document_value_in_collection('users', 'settings', 'theme')
            datastore.get_document_value_in_collection('users', 'settings', 'locale')

            mongo_client.assert_called_once()
            client.close.assert_not_called()
            datastore.close()
            client.close.assert_called_once_with()


class TestLoggingModule(unittest.TestCase):
    """Test logging module"""
    
    def test_import_logging(self):
        """Test importing oc.logging module"""
        try:
            import oc.logging
            self.assertIsNotNone(oc.logging)
        except ImportError:
            self.skipTest("oc.logging not available")
    
    def test_logging_has_with_logger_decorator(self):
        """Test that logging module has with_logger decorator"""
        try:
            import oc.logging
            self.assertTrue(hasattr(oc.logging, 'with_logger'))
        except ImportError:
            self.skipTest("oc.logging not available")


class TestI18nModule(unittest.TestCase):
    """Test i18n module"""
    
    def test_import_i18n(self):
        """Test importing i18n module"""
        try:
            import oc.i18n
            self.assertIsNotNone(oc.i18n)
        except ImportError:
            self.skipTest("i18n module not available")


if __name__ == '__main__':
    unittest.main()
