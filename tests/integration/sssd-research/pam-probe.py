"""One bounded subprocess calls real native pam_sss using a fixture-only service."""
from common import *
import ctypes as c,ctypes.util,sys
pam=c.CDLL(ctypes.util.find_library('pam'));libc=c.CDLL(None)
class Message(c.Structure):_fields_=[('style',c.c_int),('text',c.c_char_p)]
class Response(c.Structure):_fields_=[('text',c.c_void_p),('code',c.c_int)]
Callback=c.CFUNCTYPE(c.c_int,c.c_int,c.POINTER(c.POINTER(Message)),c.POINTER(c.POINTER(Response)),c.c_void_p)
libc.calloc.restype=c.c_void_p;libc.calloc.argtypes=[c.c_size_t,c.c_size_t]
libc.strdup.restype=c.c_void_p;libc.strdup.argtypes=[c.c_char_p]
@Callback
def callback(n,messages,responses,data):
 allocation=libc.calloc(n,c.sizeof(Response));arr=c.cast(allocation,c.POINTER(Response))
 for i in range(n):
  style=messages[i].contents.style
  if style in (1,2):arr[i].text=libc.strdup((b'Wrong-research-password' if len(sys.argv)>2 else b'Research-only-42') if style==1 else sys.argv[1].encode())
  elif style not in (3,4):return 19
 responses[0]=arr;return 0
class Conv(c.Structure):_fields_=[('callback',Callback),('data',c.c_void_p)]
conv=Conv(callback,None);handle=c.c_void_p()
pam.pam_start.argtypes=[c.c_char_p,c.c_char_p,c.POINTER(Conv),c.POINTER(c.c_void_p)]
pam.pam_authenticate.argtypes=[c.c_void_p,c.c_int];pam.pam_end.argtypes=[c.c_void_p,c.c_int]
start=pam.pam_start(b'sssd-research',sys.argv[1].encode(),c.byref(conv),c.byref(handle))
auth=pam.pam_authenticate(handle,0) if start==0 else None
if start==0:pam.pam_end(handle,auth)
print(json.dumps({'pam_start':start,'pam_authenticate':auth,'fixture_user':sys.argv[1]}))
sys.exit(0 if auth==0 else 1)
