from pathlib import Path
import struct
image = Path("kernel_5-15-180").read_bytes()
prefix = b"\x9f\xeb\x01\x00"
cursor = 0
while True:
    start = image.find(prefix, cursor)
    if start < 0:
        break
    cursor = start + 1
    if start + 24 > len(image):
        continue
    header = struct.unpack_from("<HBBIIIII", image, start)
    magic, version, flags, header_len, type_off, type_len, str_off, str_len = header
    if magic != 0xEB9F or version != 1 or flags != 0 or header_len < 24:
        continue
    payload_len = max(type_off + type_len, str_off + str_len)
    end = start + header_len + payload_len
    string_start = start + header_len + str_off
    if end > len(image) or string_start >= end or image[string_start] != 0:
        continue
    candidates = [(start, end)]
    break
print(f"candidates={candidates}")
start, end = candidates[0]
Path("/tmp/kilo/vmlinux.btf").write_bytes(image[start:end])
print(f"raw BTF: [0x{start:x}, 0x{end:x}) ({end - start} bytes)")
