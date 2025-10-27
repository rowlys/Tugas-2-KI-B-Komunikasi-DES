"""
Implementasi DES From-Scratch dengan Fungsionalitas Obrolan Jaringan (TCP)

Anggota Kelompok:
- Basten Andika Salim | 5025231132
- Dewa Putu Ananda Taurean Mahesa | 5025231158

CARA MENJALANKAN:

1.  Jalankan sebagai SERVER di satu komputer:
    python des_chat.py -s

2.  Jalankan sebagai KLIEN di komputer lain:
    python des_chat.py -c SERVER_IP_ADDRESS

SERVER_IP_ADDRESS adalah alamat IP dari komputer yang menjalankan server.
Kedua pengguna HARUS memasukkan Kunci 8 karakter yang sama persis.
"""

import socket
import argparse
import sys

IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

S_BOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
       15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]

KEY_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def permute(block, table):
    return [block[x - 1] for x in table]

def string_to_bits(text):
    return [int(bit) for char in text for bit in bin(ord(char))[2:].zfill(8)]

def bits_to_string(bits):
    chars = []
    for i in range(len(bits) // 8):
        byte_bits = bits[i*8:(i+1)*8]
        byte_str = ''.join(map(str, byte_bits))
        chars.append(chr(int(byte_str, 2)))
    return "".join(chars)

def bytes_to_bits(data):
    return [int(bit) for byte in data for bit in bin(byte)[2:].zfill(8)]

def bits_to_bytes(bits):
    byte_list = []
    for i in range(len(bits) // 8):
        byte_bits = bits[i*8:(i+1)*8]
        byte_str = ''.join(map(str, byte_bits))
        byte_list.append(int(byte_str, 2))
    return bytes(byte_list)

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def left_circular_shift(bits, n):
    return bits[n:] + bits[:n]

def pad(bits):
    padding_len = 8 - (len(bits) // 8 % 8)
    padding_byte_val = padding_len
    padding_bits = [int(bit) for bit in bin(padding_byte_val)[2:].zfill(8)] * padding_len
    return bits + padding_bits

def unpad(bits):
    if len(bits) < 8:
        print("Warning: Data terlalu pendek atau padding tidak valid.")
        return bits

    padding_len_bits = bits[-8:]
    padding_len_str = "".join(map(str, padding_len_bits))
    padding_len = int(padding_len_str, 2)
    
    if padding_len > 8 or padding_len == 0 or len(bits) < padding_len * 8:
         print("Warning: Data salah atau padding tidak valid.")
         return bits

    padding_is_valid = True
    expected_padding_bits = [int(bit) for bit in bin(padding_len)[2:].zfill(8)]
    
    for i in range(1, padding_len + 1):
        start_index = -i * 8
        end_index = -(i - 1) * 8 if i > 1 else None

        if bits[start_index:end_index] != expected_padding_bits:
            padding_is_valid = False
            break

    if not padding_is_valid:
        print("Warning: Padding tidak valid. Decryption mungkin gagal.")
        return bits

    return bits[:-padding_len * 8]

def generate_round_keys(key_bits):
    key_permuted = permute(key_bits, PC1)
    
    C, D = key_permuted[:28], key_permuted[28:]
    
    round_keys = []
    for i in range(16):
        C = left_circular_shift(C, KEY_SHIFTS[i])
        D = left_circular_shift(D, KEY_SHIFTS[i])
        
        combined_cd = C + D
        round_key = permute(combined_cd, PC2)
        round_keys.append(round_key)
        
    return round_keys

def feistel_function(right_half, round_key):
    expanded = permute(right_half, E)
    
    xored = xor(expanded, round_key)
    
    sbox_output = []
    for i in range(8):
        chunk = xored[i*6:(i+1)*6]
        
        row = int(str(chunk[0]) + str(chunk[5]), 2)
        col = int("".join(map(str, chunk[1:5])), 2)
        
        val = S_BOX[i][row][col]
        
        sbox_output.extend([int(b) for b in bin(val)[2:].zfill(4)])
        
    permuted_sbox_output = permute(sbox_output, P)
    
    return permuted_sbox_output

def process_block(block, round_keys, mode='encrypt'):
    block = permute(block, IP)
    L, R = block[:32], block[32:]
    
    if mode == 'decrypt':
        round_keys = round_keys[::-1] 

    for i in range(16):
        R_temp = R    
        f_result = feistel_function(R, round_keys[i]) 
        R = xor(L, f_result)
        L = R_temp
        
    final_block_unpermuted = R + L
    processed_block = permute(final_block_unpermuted, FP)
    return processed_block

def des(data, key, mode='encrypt'):
    key_bits = string_to_bits(key)
    if len(key_bits) != 64:
        raise ValueError("Key harus 8 karakter.")

    data_bits = bytes_to_bits(data)
        
    if mode == 'encrypt':
        data_bits = pad(data_bits)
        
    round_keys = generate_round_keys(key_bits)
    
    processed_bits = []
    for i in range(0, len(data_bits), 64):
        block = data_bits[i:i+64]
        processed_block = process_block(block, round_keys, mode)
        processed_bits.extend(processed_block)
        
    if mode == 'decrypt':
        processed_bits = unpad(processed_bits)

    return bits_to_bytes(processed_bits)

def start_server(key, port=12345):
    host = '0.0.0.0' 
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print(f"Server mendengarkan di port {port}...")
        print("Menunggu koneksi dari klien...")
        
        conn, addr = s.accept()
        with conn:
            print(f"Terhubung dengan {addr}")
            print("Koneksi berhasil! Anda dapat mulai mengirim pesan.")
            print("Ketik pesan Anda dan tekan Enter untuk mengirim.")
            
            while True:
                encrypted_data = conn.recv(1024)
                if not encrypted_data:
                    print("Koneksi ditutup oleh rekan.")
                    break

                try:
                    encrypted_data = encrypted_data.decode('utf-8')
                    print(f"Menerima data terenkripsi dari rekan: {encrypted_data}")
                    encrypted_data = bytes.fromhex(encrypted_data)
                    
                    decrypted_bytes = des(encrypted_data, key, mode='decrypt')
                    decrypted_bytes = decrypted_bytes.decode('utf-8')
                    print(f"Data terdekripsi dari rekan: {decrypted_bytes}")
                except Exception as e:
                    print(f"Error saat dekripsi: {e}. Pesan diabaikan.")

                reply = input("Anda: ")
                reply = reply.encode('utf-8')
                encrypted_reply = des(reply, key, mode='encrypt')
                encrypted_reply_hex = encrypted_reply.hex()

                conn.sendall(encrypted_reply_hex.encode('utf-8'))

def start_client(key, host, port=12345):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            print(f"Menyambung ke {host} di port {port}...")
            s.connect((host, port))
            print("Koneksi berhasil! Anda dapat mulai mengirim pesan.")
            print("Ketik pesan Anda dan tekan Enter untuk mengirim.")
        except Exception as e:
            print(f"Gagal terhubung ke server: {e}")
            return
            
        while True:
            msg = input("Anda: ")
            msg = msg.encode('utf-8')
            encrypted_msg = des(msg, key, mode='encrypt')
            encrypted_msg_hex = encrypted_msg.hex()
            print(f"Mengirim data terenkripsi: {encrypted_msg_hex}")
            s.sendall(encrypted_msg_hex.encode('utf-8'))

            encrypted_data = s.recv(1024)
            if not encrypted_data:
                print("Koneksi ditutup oleh server.")
                break

            try:
                encrypted_data = encrypted_data.decode('utf-8')
                print(f"Menerima data terenkripsi dari rekan: {encrypted_data}")
                decrypted_bytes = des(bytes.fromhex(encrypted_data), key, mode='decrypt')
                decrypted_bytes = decrypted_bytes.decode('utf-8')
                print(f"Data terdekripsi dari rekan: {decrypted_bytes}")
            except Exception as e:
                print(f"Error saat dekripsi: {e}. Pesan diabaikan.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Aplikasi Obrolan Terenkripsi DES")
    parser.add_argument("-s", "--server", action="store_true", help="Jalankan sebagai server")
    parser.add_argument("-c", "--client", type=str, help="Jalankan sebagai klien dan hubungkan ke HOST ini")
    
    args = parser.parse_args()

    print("==================================================")
    print("DES Communication")
    print("==================================================")

    try:
        key_input = input("Masukkan KUNCI 8 karakter (rahasia bersama): ")
        if len(key_input) != 8:
            print("\nError: Key harus tepat 8 karakter.")
            sys.exit(1)

        if args.server:
            start_server(key_input)
        elif args.client:
            start_client(key_input, args.client)
        else:
            print("Error: Anda harus memilih mode server (-s) atau klien (-c).")
            print("Contoh Server: python des_chat.py -s")
            print("Contoh Klien:  python des_chat.py -c 127.0.0.1")

    except KeyboardInterrupt:
        print("\nMenutup aplikasi obrolan...")
    except Exception as e:
        print(f"\nTerjadi kesalahan: {e}")
        