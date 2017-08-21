# Warning: this code is intended to be a quick show case, not a full binding!
import ctypes
import threading
import multiprocessing

# since the key stretching costs tons of memory and computation power,
# we need to limit the number of concurrent key stretching processes at any given time.
_global_stretch_sem = threading.Semaphore(multiprocessing.cpu_count())

class WalrusError(RuntimeError): pass

class Walrus(object):
    def __init__(self, realm, dll_path=None):
        assert isinstance(realm, bytes)
        self.dll = None
        self.dll = ctypes.CDLL(dll_path or r'Walrus.dll')
        self.handle = ctypes.c_void_p(self.dll.walrus_new(realm, ctypes.c_size_t(len(realm))))
        if not self.handle:
            raise WalrusError('failed to initialize')
        self.lock = threading.RLock()

    def __del__(self):
        if self.dll:
            self.dll.walrus_free(self.handle)
            del self.handle

    def set_rehash_interval(self, intervalsec=0):
        with self.lock:
            ret = self.dll.walrus_set_rehash_interval(self.handle, ctypes.c_uint(intervalsec))
        if ret == 0:
            raise WalrusError('failed to set rehash interval')
        return ctypes.c_uint(ret).value

    rehash_interval = property(fset=set_rehash_interval)

    def set_stretch_cost(self, cost=0):
        with self.lock:
            ret = self.dll.walrus_set_stretch_cost(self.handle, ctypes.c_uint(cost))
        if ret == 0:
            raise WalrusError('failed to set stretch cost')
        return ctypes.c_uint(ret).value

    stretch_cost = property(fset=set_stretch_cost)

    def rehash(self):
        with self.lock:
            ret = self.dll.walrus_rehash(self.handle, ctypes.c_void_p())
        if ret < 0:
            raise WalrusError('failed to rehash')
        return bool(ret)

    def import_keypairs(self, stored):
        assert isinstance(stored, bytes)
        with self.lock:
            ret = self.dll.walrus_import_keypairs(self.handle, stored, ctypes.c_size_t(len(stored)))
        if ret == 0:
            raise WalrusError('failed to import keypairs')

    def export_keypairs(self):
        buflen = ctypes.c_size_t()
        with self.lock:
            ret = ctypes.c_void_p(self.dll.walrus_export_keypairs(
                self.handle, ctypes.byref(buflen),
            ))
        if not ret:
            raise WalrusError('failed to export keypairs')
        buf = ctypes.string_at(ret, buflen.value)
        with self.lock:
            self.dll.walrus_free_str(self.handle, ret)
        return buf

    keypairs = property(fget=export_keypairs, fset=import_keypairs)

    def get_params(self):
        buflen = ctypes.c_size_t()
        with self.lock:
            ret = ctypes.c_void_p(self.dll.walrus_get_params(self.handle, ctypes.byref(buflen)))
        if not ret:
            raise WalrusError('failed to get client parameters')
        buf = ctypes.string_at(ret, buflen.value)
        with self.lock:
            self.dll.walrus_free_str(self.handle, ret)
        return buf

    params = property(fget=get_params)

    def decode_secret(self, user, secret):
        try:
            return WalrusSecret(self, user, secret)
        except Exception:
            return WalrusDummySecret()

class WalrusSecret(object):
    def __init__(self, walrus, user, secret):
        assert isinstance(user, bytes) and isinstance(secret, bytes)
        self.dll = None
        with walrus.lock:
            ret = ctypes.c_void_p(walrus.dll.walrus_decode_secret(
                walrus.handle, user, ctypes.c_size_t(len(user)),
                secret, ctypes.c_size_t(len(secret)),
            ))
        if not ret:
            raise WalrusError('failed to decode secret')

        self.dll = walrus.dll
        self.handle = ret
        self.lock = threading.RLock()

    def __del__(self):
        if self.dll:
            self.dll.walrus_free_secret(self.handle)
            del self.handle

    def verify(self, stored):
        assert stored is None or isinstance(stored, bytes)
        storedlen = len(stored) if stored else 0
        with _global_stretch_sem:
            with self.lock:
                ret = self.dll.walrus_verify_secret(self.handle, stored, ctypes.c_size_t(storedlen))
        if ret == 0:
            raise WalrusError('failed to verify secret')
        return ret == 2 # will return True when reexport is needed

    def export(self):
        buflen = ctypes.c_size_t()
        with _global_stretch_sem:
            with self.lock:
                ret = ctypes.c_void_p(self.dll.walrus_export_secret(
                    self.handle, ctypes.byref(buflen),
                ))
        if not ret:
            raise WalrusError('failed to export secret')
        buf = ctypes.string_at(ret, buflen.value)
        with self.lock:
            self.dll.walrus_free_secret_str(self.handle, ret)
        return buf

    def make_result(self, result):
        assert isinstance(result, bytes)
        buflen = ctypes.c_size_t()
        with self.lock:
            ret = ctypes.c_void_p(self.dll.walrus_make_result(
                self.handle, result, ctypes.c_size_t(len(result)), ctypes.byref(buflen),
            ))
        if not ret:
            raise WalrusError('failed to make result')
        buf = ctypes.string_at(ret, buflen.value)
        with self.lock:
            self.dll.walrus_free_secret_str(self.handle, ret)
        return buf

class WalrusDummySecret(object):
    def __nonzero__(self): return False
    def verify(self, stored): raise WalrusError('failed to verify secret')
    def export(self): raise WalrusError('failed to export secret')
    def make_result(self, result): raise WalrusError('failed to make result')

