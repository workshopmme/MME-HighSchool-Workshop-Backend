import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

class WorkshopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.environment = patch.dict(os.environ, {'DB_PATH': str(Path(cls.directory.name) / 'workshop.db'), 'ADMIN_CODE': 'test-code'})
        cls.environment.start()
        spec = importlib.util.spec_from_file_location('workshop_server', Path(__file__).with_name('server.py'))
        cls.server = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.server)
        cls.server.app.config['TESTING'] = True

    @classmethod
    def tearDownClass(cls):
        cls.environment.stop()
        cls.directory.cleanup()

    def setUp(self):
        self.server.DB_PATH = str(Path(self.directory.name) / f'{self._testMethodName}.db')
        self.server.init()
        self.client = self.server.app.test_client()
        self.auth = {'x-admin-code': 'test-code'}

    def payload(self, **changes):
        data = {'schoolName': 'RHU High School', 'interestedMajor': 'Mechatronics Engineering', 'members': [
            {'name': 'Maya Test', 'email': 'maya@example.com', 'phone': '+961 70 000 000'},
            {'name': 'Karim Test', 'email': 'karim@example.com', 'phone': '+961 71 000 000'},
        ]}
        data.update(changes)
        return data

    def create(self, **changes):
        response = self.client.post('/api/teams', json=self.payload(**changes))
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()['id']

    def test_registration_saves_team_and_members(self):
        team_id = self.create()
        team = self.client.get(f'/api/admin/teams/{team_id}', headers=self.auth).get_json()
        self.assertEqual((team['school_name'], team['interested_major'], len(team['members'])), ('RHU High School', 'Mechatronics Engineering', 2))

    def test_team_size_and_member_fields_are_validated(self):
        for members in ([], [self.payload()['members'][0]] * 4, [{'name': 'Only name'}]):
            self.assertEqual(self.client.post('/api/teams', json=self.payload(members=members)).status_code, 400)

    def test_check_in_updates_team_and_student_statistics(self):
        first = self.create()
        self.create(schoolName='Another School', interestedMajor='Mechanical Engineering', members=[{'name': 'Sara', 'email': 'sara@example.com', 'phone': '123'}])
        stats = self.client.get('/api/admin/stats', headers=self.auth).get_json()
        self.assertEqual((stats['totalTeams'], stats['totalStudents'], stats['totalSchools'], stats['enteredTeams'], stats['enteredStudents']), (2, 3, 2, 0, 0))
        response = self.client.post(f'/api/admin/teams/{first}/entered', json={'value': True}, headers=self.auth)
        self.assertEqual(response.status_code, 200)
        stats = self.client.get('/api/admin/stats', headers=self.auth).get_json()
        self.assertEqual((stats['enteredTeams'], stats['enteredStudents']), (1, 2))

    def test_admin_token_is_issued_and_works(self):
        login = self.client.post('/api/admin/login', json={'code': 'test-code'})
        self.assertEqual(login.status_code, 200)
        token = login.get_json()['adminToken']
        self.assertEqual(self.client.get('/api/admin/state', headers={'Authorization': 'Bearer ' + token}).status_code, 200)

if __name__ == '__main__':
    unittest.main()