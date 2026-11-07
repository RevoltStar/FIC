#!/usr/bin/env python3
"""Bounded I4 native-library/parser probe; DISPOSABLE Docker root only.

Not FIC apply E2E or authentication. Public ABI constants/layout:
libpwquality 1.4.5 pwquality.h; Openwall passwdqc 2.0.3 passwdqc.h.
"""
import ctypes as C
import ctypes.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

assert Path('/.dockerenv').exists() and os.geteuid() == 0, 'disposable Docker root required'
result = {}

def library(name):
    path = ctypes.util.find_library(name)
    assert path, name
    return C.CDLL(path)

if os.uname().sysname != 'Linux':
    raise SystemExit(97)
if 'ID=altlinux' in Path('/etc/os-release').read_text():
    version = subprocess.check_output(['rpm', '-q', 'libpasswdqc'], text=True).strip()
    assert '2.0.3-' in version, version
    class QC(C.Structure):
        _fields_ = [('min', C.c_int * 5), ('max', C.c_int), ('passphrase', C.c_int),
                    ('match', C.c_int), ('similar', C.c_int), ('random', C.c_int),
                    ('wordlist', C.c_void_p), ('denylist', C.c_void_p), ('filter', C.c_void_p)]
    class PAM(C.Structure):
        _fields_ = [('flags', C.c_int), ('retry', C.c_int)]
    class Params(C.Structure):
        _fields_ = [('qc', QC), ('pam', PAM)]
    lib = library('passwdqc')
    lib.passwdqc_params_reset.argtypes = [C.POINTER(Params)]
    lib.passwdqc_params_free.argtypes = [C.POINTER(Params)]
    lib.passwdqc_params_load.argtypes = [C.POINTER(Params), C.POINTER(C.c_void_p), C.c_char_p]
    lib.passwdqc_params_parse.argtypes = [C.POINTER(Params), C.POINTER(C.c_void_p), C.c_int, C.POINTER(C.c_char_p)]
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / 'base'; nested = Path(tmp) / 'nested'
        nested.write_text('match=5\nretry=3\n')
        for mode, mask in [('none', 0), ('users', 1), ('everyone', 3)]:
            base.write_text(f'min=disabled,24,11,8,7\nconfig={nested}\nmatch=7\nenforce={mode}\n')
            params = Params(); lib.passwdqc_params_reset(C.byref(params)); reason = C.c_void_p()
            assert lib.passwdqc_params_load(C.byref(params), C.byref(reason), os.fsencode(base)) == 0
            assert params.pam.flags & 3 == mask and params.qc.match == 7 and params.pam.retry == 3
            # Native inline argv follows config= at its exact argv position.
            argv = (C.c_char_p * 3)(b'match=9', os.fsencode('config=' + str(base)), b'retry=4')
            assert lib.passwdqc_params_parse(C.byref(params), C.byref(reason), 3, argv) == 0
            assert params.qc.match == 7 and params.pam.retry == 4
            result[mode] = {'root_mask': mask, 'nested_then_primary_match': 7, 'inline_retry': 4}
            lib.passwdqc_params_free(C.byref(params))
    result['version'] = version
else:
    lib = library('pwquality')
    lib.pwquality_default_settings.restype = C.c_void_p
    lib.pwquality_free_settings.argtypes = [C.c_void_p]
    lib.pwquality_read_config.argtypes = [C.c_void_p, C.c_char_p, C.POINTER(C.c_void_p)]
    lib.pwquality_get_int_value.argtypes = [C.c_void_p, C.c_int, C.POINTER(C.c_int)]
    lib.pwquality_set_option.argtypes = [C.c_void_p, C.c_char_p]
    directory = Path('/etc/security/pwquality.conf.d'); directory.mkdir(exist_ok=True)
    (directory / '10-i4.conf').write_text('minlen=10\n')
    (directory / '90-i4.conf').write_text('minlen=14\n')
    Path('/etc/security/pwquality.conf').write_text('minlen=18\nminlen=20\ndcredit=-2\nenforce_for_root=0\n')
    settings = lib.pwquality_default_settings(); assert settings
    aux = C.c_void_p()
    assert lib.pwquality_read_config(settings, None, C.byref(aux)) == 0
    def get(identifier):
        value = C.c_int()
        assert lib.pwquality_get_int_value(settings, identifier, C.byref(value)) == 0
        return value.value
    assert get(3) == 20 and get(4) == -2 and get(19) == 1
    assert lib.pwquality_set_option(settings, b'minlen=24') == 0 and get(3) == 24
    result['pwquality'] = {'primary_after_dropins_last_wins': 20, 'inline_override': 24,
                           'negative_credit': -2, 'enforce_for_root_equals_zero_is_set': True}
    lib.pwquality_free_settings(settings)
    # Native libpam helper used by supported pwhistory.conf implementations.
    pam = library('pam'); libc = C.CDLL(None)
    pam.pam_modutil_search_key.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p]
    pam.pam_modutil_search_key.restype = C.c_void_p
    libc.free.argtypes = [C.c_void_p]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'pwhistory.conf'; path.write_text('ReMeMbEr=3\nremember=0\nenforce_for_root=0\n')
        def search(key):
            ptr = pam.pam_modutil_search_key(None, os.fsencode(path), key)
            assert ptr
            value = C.string_at(ptr).decode(); libc.free(ptr); return value
        assert search(b'remember') == '3' and search(b'enforce_for_root') == '0'
    result['libpam_helper'] = 'first match, case insensitive; flag value present even when 0'
    result['versions'] = subprocess.check_output(['dpkg-query', '-W', 'libpwquality1', 'libpam0g', 'libpam-modules'], text=True)
print(json.dumps({'result': 'PASS', 'kind': 'native-library/parser only', 'facts': result}, indent=2))
