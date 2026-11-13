#!/usr/bin/env python3
"""Generate a synthetic OpenSSL SM2 vector; no plugin/BC implementation is used."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import tempfile


def read_der(data, offset=0):
    tag = data[offset]
    size = data[offset + 1]
    cursor = offset + 2
    if size & 128:
        count = size & 127
        size = int.from_bytes(data[cursor:cursor + count], 'big')
        cursor += count
    end = cursor + size
    if end > len(data):
        raise ValueError('Truncated DER')
    return tag, data[cursor:end], end


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl', default='openssl')
    parser.add_argument('--output', type=Path, default=Path('src/test/resources/crypto/sm2-openssl-vector.json'))
    args = parser.parse_args()
    run = lambda *parts: subprocess.run([args.openssl, *map(str, parts)], check=True, capture_output=True).stdout
    plaintext = 'SM2 independent vector / 中文'.encode('utf-8')
    with tempfile.TemporaryDirectory(prefix='uce-sm2-vector-') as temp:
        root = Path(temp)
        private = root / 'private.pem'
        public = root / 'public.pem'
        message = root / 'message.bin'
        cipher = root / 'cipher.der'
        run('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:sm2', '-out', private)
        run('pkey', '-in', private, '-pubout', '-out', public)
        private_der = run('pkcs8', '-topk8', '-nocrypt', '-in', private, '-outform', 'DER')
        public_der = run('pkey', '-in', private, '-pubout', '-outform', 'DER')
        message.write_bytes(plaintext)
        run('pkeyutl', '-encrypt', '-pubin', '-inkey', public, '-in', message, '-out', cipher)
        assert run('pkeyutl', '-decrypt', '-inkey', private, '-in', cipher) == plaintext
        encoded = cipher.read_bytes()
        tag, sequence, end = read_der(encoded)
        assert tag == 0x30 and end == len(encoded)
        cursor = 0
        parts = []
        for expected_tag in [0x02, 0x02, 0x04, 0x04]:
            tag, value, cursor = read_der(sequence, cursor)
            assert tag == expected_tag
            parts.append(value)
        assert cursor == len(sequence)
        x, y, c3, c2 = parts
        assert len(c3) == 32
        # BC 1.70 Cipher("SM2") default is C1C2C3; OpenSSL emits ASN.1 (x,y,C3,C2).
        raw = b'\x04' + int.from_bytes(x, 'big').to_bytes(32, 'big') + int.from_bytes(y, 'big').to_bytes(32, 'big') + c2 + c3
        b64 = lambda value: base64.b64encode(value).decode('ascii')
        vector = {'implementation': run('version').decode().strip(), 'plaintextUtf8': plaintext.decode(),
                  'publicKeyBase64': b64(public_der), 'privateKeyBase64': b64(private_der),
                  'ciphertextBase64': b64(raw), 'ciphertextFormat': 'raw C1C2C3, uncompressed C1',
                  'opensslCiphertextDerBase64': b64(encoded)}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(vector, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(args.output)


if __name__ == '__main__':
    main()
