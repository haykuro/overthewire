import json

class PasswordCache(object):
    CACHE_FILE = "./pass_cache.json"

    def __init__(self, filename=None):
        if filename:
            self.CACHE_FILE = filename

    def read(self):
        out = {}
        text_to_read = ""

        try:
            with open(self.CACHE_FILE, 'r') as filehandle:
                text_to_read = filehandle.read()
                filehandle.close()
        except FileNotFoundError:
            new_cache = {}
            self.write(new_cache)
            text_to_read = json.dumps(new_cache)

        if text_to_read:
            out = json.loads(text_to_read)

        return out

    def get(self, level):
        obj = self.read()

        if not obj:
            return None

        return obj.get(level)


    def write(self, obj):
        text_to_write = json.dumps(obj)

        with open(self.CACHE_FILE, 'w') as filehandle:
            filehandle.write(text_to_write)
            filehandle.close()

    def write_pass(self, level, password):
        obj = self.read()

        obj[level] = password

        text_to_write = json.dumps(obj)

        with open(self.CACHE_FILE, 'w') as filehandle:
            filehandle.write(text_to_write)
            filehandle.close()