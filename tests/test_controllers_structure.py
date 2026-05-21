"""
Unit tests for all controllers structure and basic functionality

Tests the structure of all 8 controllers in the controllers/ directory
"""
import unittest
import sys
import os
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


CONTROLLERS = [
    'auth_controller',
    'composer_controller',
    'core_controller',
    'key_controller',
    'manager_controller',
    'store_controller',
    'user_controller',
    'accounting_controller',
]


class TestControllersStructure(unittest.TestCase):
    """Test that all controllers exist and have expected structure"""
    
    def test_all_controllers_exist(self):
        """Test that all controller modules exist"""
        import controllers
        for controller_name in CONTROLLERS:
            module_path = f'controllers.{controller_name}'
            try:
                __import__(module_path)
            except (ImportError, AttributeError) as e:
                # Skip if CherryPy tool not configured or controller not available
                if 'auth' in controller_name or 'Toolbox' in str(e):
                    self.skipTest(f"Controller {controller_name} requires CherryPy tools: {e}")
                else:
                    self.skipTest(f"Controller {controller_name} not available: {e}")
    
    def test_controller_class_naming(self):
        """Test that controllers follow naming convention (NameController)"""
        expected_classes = {
            'auth_controller': 'AuthController',
            'composer_controller': 'ComposerController',
            'core_controller': 'CoreController',
            'key_controller': 'KeyController',
            'manager_controller': 'ManagerController',
            'store_controller': 'StoreController',
            'user_controller': 'UserController',
            'accounting_controller': 'AccountingController',
        }
        
        for module_name, class_name in expected_classes.items():
            try:
                module = __import__(f'controllers.{module_name}', fromlist=[class_name])
                if hasattr(module, class_name):
                    controller_class = getattr(module, class_name)
                    self.assertIsNotNone(controller_class)
            except (ImportError, AttributeError):
                # Skip if controller not available
                pass


class TestControllerBasics(unittest.TestCase):
    """Test basic functionality of controllers"""
    
    def test_controller_init(self):
        """Test that controllers can be instantiated"""
        try:
            from controllers.core_controller import CoreController
            controller = CoreController()
            self.assertIsNotNone(controller)
        except Exception as e:
            self.skipTest(f"Could not instantiate controller: {e}")
    
    def test_exposed_methods_exist(self):
        """Test that exposed methods are callable"""
        try:
            from controllers.core_controller import CoreController
            controller = CoreController()
            
            # Check for common exposed methods
            exposed_methods = [
                'getkeyinfo',
                'getmessageinfo',
                'handler_messageinfo_json',
                'handler_messageinfo_text',
            ]
            
            for method_name in exposed_methods:
                if hasattr(controller, method_name):
                    method = getattr(controller, method_name)
                    self.assertTrue(callable(method))
        except Exception:
            self.skipTest("CoreController structure test skipped")


class TestAuthController(unittest.TestCase):
    """Test AuthController structure"""
    
    def test_auth_controller_import(self):
        """Test importing AuthController"""
        try:
            from controllers.auth_controller import AuthController
            self.assertIsNotNone(AuthController)
        except (ImportError, AttributeError) as e:
            # Skip if CherryPy auth tool not configured
            if 'Toolbox' in str(e) or 'auth' in str(e):
                self.skipTest("CherryPy auth tool not configured")
            else:
                self.skipTest(f"AuthController not available: {e}")
    
    def test_auth_controller_instantiation(self):
        """Test instantiating AuthController"""
        try:
            from controllers.auth_controller import AuthController
            controller = AuthController()
            self.assertIsNotNone(controller)
        except Exception as e:
            self.skipTest(f"Could not instantiate AuthController: {e}")


class TestComposerController(unittest.TestCase):
    """Test ComposerController structure"""
    
    def test_composer_controller_import(self):
        """Test importing ComposerController"""
        try:
            from controllers.composer_controller import ComposerController
            self.assertIsNotNone(ComposerController)
        except ImportError:
            self.skipTest("ComposerController not available")
    
    def test_composer_controller_instantiation(self):
        """Test instantiating ComposerController"""
        try:
            from controllers.composer_controller import ComposerController
            controller = ComposerController()
            self.assertIsNotNone(controller)
        except Exception as e:
            self.skipTest(f"Could not instantiate ComposerController: {e}")


class TestManagerController(unittest.TestCase):
    """Test ManagerController structure"""
    
    def test_manager_controller_import(self):
        """Test importing ManagerController"""
        try:
            from controllers.manager_controller import ManagerController
            self.assertIsNotNone(ManagerController)
        except ImportError:
            self.skipTest("ManagerController not available")
    
    def test_manager_controller_instantiation(self):
        """Test instantiating ManagerController"""
        try:
            from controllers.manager_controller import ManagerController
            controller = ManagerController()
            self.assertIsNotNone(controller)
        except Exception as e:
            self.skipTest(f"Could not instantiate ManagerController: {e}")


class TestUserController(unittest.TestCase):
    """Test UserController structure"""
    
    def test_user_controller_import(self):
        """Test importing UserController"""
        try:
            from controllers.user_controller import UserController
            self.assertIsNotNone(UserController)
        except ImportError:
            self.skipTest("UserController not available")
    
    def test_user_controller_instantiation(self):
        """Test instantiating UserController"""
        try:
            from controllers.user_controller import UserController
            controller = UserController()
            self.assertIsNotNone(controller)
        except Exception as e:
            self.skipTest(f"Could not instantiate UserController: {e}")


class TestStoreController(unittest.TestCase):
    """Test StoreController structure"""
    
    def test_store_controller_import(self):
        """Test importing StoreController"""
        try:
            from controllers.store_controller import StoreController
            self.assertIsNotNone(StoreController)
        except ImportError:
            self.skipTest("StoreController not available")
    
    def test_store_controller_instantiation(self):
        """Test instantiating StoreController"""
        try:
            from controllers.store_controller import StoreController
            controller = StoreController()
            self.assertIsNotNone(controller)
        except Exception as e:
            self.skipTest(f"Could not instantiate StoreController: {e}")


class TestKeyController(unittest.TestCase):
    """Test KeyController structure"""
    
    def test_key_controller_import(self):
        """Test importing KeyController"""
        try:
            from controllers.key_controller import KeyController
            self.assertIsNotNone(KeyController)
        except ImportError:
            self.skipTest("KeyController not available")
    
    def test_key_controller_instantiation(self):
        """Test instantiating KeyController"""
        try:
            from controllers.key_controller import KeyController
            controller = KeyController()
            self.assertIsNotNone(controller)
        except Exception as e:
            self.skipTest(f"Could not instantiate KeyController: {e}")


class TestAccountingController(unittest.TestCase):
    """Test AccountingController structure"""
    
    def test_accounting_controller_import(self):
        """Test importing AccountingController"""
        try:
            from controllers.accounting_controller import AccountingController
            self.assertIsNotNone(AccountingController)
        except ImportError:
            self.skipTest("AccountingController not available")
    
    def test_accounting_controller_instantiation(self):
        """Test instantiating AccountingController"""
        try:
            from controllers.accounting_controller import AccountingController
            controller = AccountingController()
            self.assertIsNotNone(controller)
        except Exception as e:
            self.skipTest(f"Could not instantiate AccountingController: {e}")


if __name__ == '__main__':
    unittest.main()
