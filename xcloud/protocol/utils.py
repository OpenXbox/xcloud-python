def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def int_to_bytes(i, n_bytes):
    return i.to_bytes(n_bytes, byteorder='big')