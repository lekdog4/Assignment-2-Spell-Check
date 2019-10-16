import time
import unittest
import subprocess
from bs4 import BeautifulSoup
import requests


class MyTestCase(unittest.TestCase):
     username = "Name1234"
     password = "test"
     phone = "7032353030"


    #Test Case Verifies Register Form returned by verifying
     def test_register_form(self):
         with requests.Session() as s:
            url = "http://127.0.0.1:5000/register"
            r = s.get(url)
            soup = BeautifulSoup(r.content, "html.parser")
            csrfToken = soup.find('input', attrs={'name': 'csrf_token'})['value']

            r = s.post(url, data = {'username':'Name1234','password':'Password123$','phone':'7032353030', 'csrf_token':csrfToken})
            self.assertIsNotNone(soup.find(id='uname'))
            self.assertIsNotNone(soup.find(id='pword'))
            self.assertIsNotNone(soup.find(id='2fa'))
            success = soup.find(id='success')
            self.assertEqual('none failure', success.get_text().lower().strip())

            #Test Case Verifies Login Success
            def test_login_success(self):
                    url = "http://127.0.0.1:5000/login"
                    r = s.get(url)
                    soup = BeautifulSoup(r.content, "html.parser")
                    csrfToken = soup.find('input', attrs={'name': 'csrf_token'})['value']

                    r = s.post(url, data = {'username':'Name1234','password':'Password123$','phone':'7032353030', 'csrf_token':csrfToken})
                    self.assertIsNotNone(soup.find(id='uname'))
                    self.assertIsNotNone(soup.find(id='pword'))
                    self.assertIsNotNone(soup.find(id='2fa'))
                    success = soup.find(id='result')
                    self.assertEqual('none failure', success.get_text().lower().strip())

            #Test Case Verifies Spell Check Success
            def test_login_spell_check_successs(self):
                with requests.Session() as s:
                    url = "http://127.0.0.1:5000/spell_check"
                    r = s.get(url)
                    soup = BeautifulSoup(r.content, "html.parser")
                    csrfToken = soup.find('input', attrs={'name': 'csrf_token'})['value']

                    r = s.post(url, data = {'inputtext':'Take a sad sogn and make it betta', 'csrf_token':csrfToken})
                    
                    soup = BeautifulSoup(r.content, "html.parser")

                    misspelled = soup.find(id='misspelled')

                    self.assertEqual("sogn, betta", misspelled.get_text().strip())

                    textout = soup.find(id='textout')
                    self.assertIsNotNone(textout)
                    self.assertEqual("Take a sad sogn and make it betta", textout.get_text().strip())


if __name__ == '__main__':
    unittest.main()
