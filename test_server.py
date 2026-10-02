"""Integration checks use a temporary DB and do not touch real account data."""
import http.cookiejar
import json
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from http.server import ThreadingHTTPServer
import server

class FlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        server.DATA=Path(cls.tmp.name)
        server.DB=server.DATA/'test.sqlite3'
        server.initialize()
        cls.http=ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        cls.base=f'http://127.0.0.1:{cls.http.server_port}/api/'
        threading.Thread(target=cls.http.serve_forever,daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.tmp.cleanup()

    def client(self):
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self,c,path,data=None,origin=None):
        headers={'Content-Type':'application/json'}
        if origin: headers['Origin']=origin
        req=urllib.request.Request(self.base+path,data=json.dumps(data).encode() if data is not None else None,headers=headers)
        try:
            with c.open(req) as r: return r.status,json.load(r)
        except urllib.error.HTTPError as e: return e.code,json.load(e)

    def test_complete_two_user_flow_and_isolation(self):
        eng,student,outsider=self.client(),self.client(),self.client()
        for c,email,name,role in ((eng,'eng@example.com','陈工程师','engineer'),(student,'student@example.com','小林','student'),(outsider,'other@example.com','小夏','student')):
            code,r=self.call(c,'register',dict(email=email,password='testing-password',name=name,role=role))
            self.assertEqual(code,200,r)
            self.assertEqual(r['user']['role'],role)
        self.assertEqual(self.call(eng,'profile',dict(name='陈工程师',bio='机械设计与制造，指导桌面机械臂。',specialty='机械工程',years=35,fee='公益指导',available=True))[0],200)
        code,r=self.call(student,'engineers')
        self.assertEqual(code,200)
        eid=r['engineers'][0]['id']
        self.assertNotIn('email',r['engineers'][0])
        code,r=self.call(student,'requests',dict(engineer_id=eid,title='机械臂',question='请指导机械臂的关节和抓手设计。'))
        self.assertEqual(code,201,r)
        rid=r['id']
        self.assertEqual(self.call(student,'messages',dict(request_id=rid,body='提前发消息'))[0],403)
        self.assertEqual(self.call(student,'request-status',dict(id=rid,status='active'))[0],403)
        self.assertEqual(self.call(outsider,f'messages?request_id={rid}')[0],403)
        self.assertEqual(self.call(eng,'request-status',dict(id=rid,status='active'))[0],200)
        self.assertEqual(self.call(student,'messages',dict(request_id=rid,body='<script>hello</script>'))[0],201)
        self.assertEqual(self.call(eng,'requests')[1]['requests'][0]['unread'],1)
        code,r=self.call(eng,f'messages?request_id={rid}')
        self.assertEqual(len(r['messages']),1)
        mid=r['messages'][0]['id']
        self.assertEqual(self.call(eng,'message-read',dict(request_id=rid,last_id=mid))[0],200)
        self.assertEqual(self.call(eng,'requests')[1]['requests'][0]['unread'],0)
        self.assertEqual(self.call(eng,'messages',dict(request_id=rid,body='先测试关节的运动范围。'))[0],201)
        self.assertEqual(len(self.call(student,f'messages?request_id={rid}')[1]['messages']),2)
        self.assertEqual(self.call(outsider,'messages',dict(request_id=rid,body='不应发送'))[0],403)
        self.assertEqual(self.call(eng,'request-status',dict(id=rid,status='completed'))[0],200)
        self.assertEqual(self.call(student,'messages',dict(request_id=rid,body='完成后不可发送'))[0],403)
        self.assertEqual(self.call(student,f'messages?request_id={rid}')[0],200)
        self.assertEqual(self.call(eng,'request-status',dict(id=rid,status='active'))[0],409)
        self.assertEqual(self.call(student,'logout',{})[0],200)
        self.assertIsNone(self.call(student,'me')[1]['user'])
        self.assertEqual(self.call(student,'requests')[0],401)
        self.assertEqual(self.call(student,'login',dict(email='student@example.com',password='wrong-password'))[0],401)
        self.assertEqual(self.call(student,'login',dict(email='student@example.com',password='testing-password'))[0],200)
        self.assertEqual(len(self.call(student,'requests')[1]['requests']),1)
        self.assertEqual(self.call(student,'logout',{},origin='http://evil.example')[0],403)
        with server.connect() as db:
            u=db.execute('SELECT * FROM users WHERE email=?',('student@example.com',)).fetchone()
            self.assertNotEqual(u['password'],'testing-password')

    def test_invalid_registration_and_unknown_api(self):
        c=self.client()
        self.assertEqual(self.call(c,'register',dict(email='bad',password='testtest',name='A',role='student'))[0],400)
        self.assertEqual(self.call(c,'register',dict(email='a@example.com',password='testtest',name='A',role='admin'))[0],400)
        self.assertEqual(self.call(c,'requests')[0],401)

    def test_admin_setup_role_selection_and_access(self):
        admin,regular=self.client(),self.client()
        self.assertEqual(self.call(regular,'register',dict(email='regular@example.com',password='testing-password',name='普通用户',role='student'))[0],200)
        self.assertEqual(self.call(regular,'admin/overview')[0],403)
        self.assertEqual(self.call(admin,'admin/overview')[0],401)
        payload=dict(email='owner@example.com',password='owner-test-password',name='管理员',setup_key='wrong-key')
        self.assertEqual(self.call(admin,'admin-setup',payload)[0],403)
        payload['setup_key']=(server.DATA/'admin-setup-key.txt').read_text()
        self.assertEqual(self.call(admin,'admin-setup',payload)[0],200)
        self.assertFalse(self.call(admin,'admin-setup-status')[1]['needed'])
        self.assertEqual(self.call(admin,'admin-setup',payload)[0],409)
        self.assertEqual(self.call(admin,'login',dict(email=payload['email'],password=payload['password'],role='engineer'))[0],403)
        code,r=self.call(admin,'login',dict(email=payload['email'],password=payload['password'],role='admin'))
        self.assertEqual(code,200,r)
        self.assertTrue(r['user']['is_admin'])
        self.assertTrue(self.call(admin,'me')[1]['user']['is_admin'])
        code,r=self.call(admin,'admin/overview')
        self.assertEqual(code,200)
        self.assertTrue(any(u['email']=='regular@example.com' for u in r['users']))
        for u in r['users']:
            self.assertNotIn('password',u)
            self.assertNotIn('salt',u)
        self.assertEqual(self.call(regular,'login',dict(email='regular@example.com',password='testing-password',role='admin'))[0],403)
        self.assertEqual(self.call(regular,'register',dict(email='rogue@example.com',password='testing-password',name='不合法管理员',role='admin'))[0],400)
        self.assertEqual(self.call(regular,'admin/conversation?request_id=1')[0],403)

if __name__=='__main__': unittest.main(verbosity=2)
