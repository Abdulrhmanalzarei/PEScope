import json, struct, tempfile, unittest
from pathlib import Path
from pescope.pe import parse, ascii_strings, entropy, rva_to_offset
from pescope.config import load_config
from pescope.errors import ConfigError

def minimal_pe():
    d = bytearray(512)
    d[:2] = b'MZ'
    struct.pack_into('<I', d, 60, 128)
    d[128:132] = b'PE\x00\x00'
    struct.pack_into('<HHIIIHH', d, 132, 332, 1, 0, 0, 0, 224, 258)
    o = 152
    struct.pack_into('<H', d, o, 267)
    struct.pack_into('<I', d, o + 16, 4096)
    struct.pack_into('<I', d, o + 28, 4194304)
    struct.pack_into('<I', d, o + 32, 4096)
    struct.pack_into('<I', d, o + 36, 512)
    s = o + 224
    d[s:s + 8] = b'.text\x00\x00\x00'
    struct.pack_into('<I', d, s + 8, 16)
    struct.pack_into('<I', d, s + 12, 4096)
    struct.pack_into('<I', d, s + 16, 16)
    struct.pack_into('<I', d, s + 20, 512)
    d[512:528] = b'HELLO_TEST_STRING'
    return bytes(d)

class TestPEScope(unittest.TestCase):

    def test_parse(self):
        with tempfile.TemporaryDirectory() as x:
            p = Path(x) / 'a.exe'
            p.write_bytes(minimal_pe())
            pe = parse(str(p))
            self.assertEqual(pe.machine, 332)
            self.assertEqual(pe.entry_point, 4096)
            self.assertEqual(pe.sections[0].name, '.text')

    def test_strings(self):
        self.assertEqual(ascii_strings(b'\x00HELLO_WORLD\x00x', 5)[0][1], 'HELLO_WORLD')

    def test_entropy(self):
        self.assertGreater(entropy(b'ABCD' * 100), 1)

    def test_rva(self):
        with tempfile.TemporaryDirectory() as x:
            p = Path(x) / 'a.exe'
            p.write_bytes(minimal_pe())
            self.assertEqual(rva_to_offset(parse(str(p)), 4096), 512)

    def test_bad_file(self):
        with tempfile.TemporaryDirectory() as x:
            p = Path(x) / 'bad'
            p.write_bytes(b'bad')
            with self.assertRaises(Exception):
                parse(str(p))

    def test_config(self):
        with tempfile.TemporaryDirectory() as x:
            p = Path(x) / 'c.json'
            p.write_text(json.dumps({'min_string_length': 8, 'entropy_threshold': 7.5}))
            c = load_config(str(p))
            self.assertEqual(c['min_string_length'], 8)
            self.assertEqual(c['entropy_threshold'], 7.5)

    def test_bad_config(self):
        with tempfile.TemporaryDirectory() as x:
            p = Path(x) / 'c.json'
            p.write_text('{"min_string_length":0}')
            with self.assertRaises(ConfigError):
                load_config(str(p))
