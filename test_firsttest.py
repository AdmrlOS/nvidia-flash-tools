import unittest
from unittest.mock import patch,Mock
from types import SimpleNamespace
import flow,thor

class FirstTestPolicy(unittest.TestCase):
    def test_firsttest_no_qualification_record_required(self):
        flow.experimental_authorization(SimpleNamespace(experimental_first_test=True,security_observation=lambda identity:None))
    def test_no_uefi_observation_not_authorized(self):
        with self.assertRaisesRegex(ValueError,'security observation'):
            flow.experimental_authorization(SimpleNamespace(experimental_first_test=True))
    def test_explicit_observation_refuses_unknown_enabled(self):
        for answer in ['unknown','enabled','yes','']:
            with patch('builtins.input',return_value=answer):
                with self.assertRaisesRegex(ValueError,'Secure Boot'):
                    thor.security_observation({'ecid':'test-only'})
    def test_install_reaches_real_workspace_without_qualification(self):
        args=SimpleNamespace(board='thor',experimental_first_test=True,security_observation=lambda identity:'secure-boot-disabled-observed',output='mock',nvidia_archive='mock',sample_rootfs='mock',guided_approval=Mock())
        with patch('security.trusted_directory',return_value=999),patch('os.close'),patch('workspace.Workspace') as workspace,patch('flow.thor_session',return_value={'actual':'edge'}) as session:
            self.assertEqual(flow.install(args,{'nvidia':{}},[]),{'actual':'edge'})
            workspace.return_value.__enter__.return_value.prepare.assert_called_once()
            session.assert_called_once()
