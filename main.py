import requests
import json
import binascii
import base64
import os
from urllib.parse import quote
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# --- Decryption Logic ---
def np_decode(hex_str, key="npmanager"):
    try:
        data = binascii.unhexlify(hex_str)
        key_len = len(key)
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ ord(key[i % key_len])
        return result.decode('utf-8')
    except:
        return ""

ENCRYPTED_AES_KEY = "5E415D5657590455455D155C56565852"
REAL_AES_KEY = np_decode(ENCRYPTED_AES_KEY)

def vpn_decrypt(long_hex_input):
    try:
        ascii_payload = binascii.unhexlify(long_hex_input).decode('utf-8')
        if ":" not in ascii_payload: return None
        parts = ascii_payload.split(":")
        ciphertext_b64 = parts[0]
        iv_b64 = parts[1]
        key_bytes = REAL_AES_KEY.encode('utf-8')
        iv_bytes = base64.b64decode(iv_b64)
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        decrypted_bytes = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
        return decrypted_bytes.decode('utf-8')
    except:
        return None

def fetch_and_process():
    url = "http://host-chi.ir/api/v2/servers-free"
    headers = {"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; SM-G960F)"}
    
    valid_configs = []
    
    try:
        response = requests.post(url, headers=headers, timeout=15)
        server_list = response.json()
        
        if isinstance(server_list, list):
            for item in server_list:
                hex_str = item.get('config')
                name = item.get('HostName') or "VPN"
                flag = item.get('flag')
                
                display_name = f"{name} {flag.upper()}" if flag else name
                safe_name = quote(display_name)

                if hex_str:
                    decrypted = vpn_decrypt(hex_str)
                    if decrypted and ("://" in decrypted):
                        base_config = decrypted.split("#")[0]
                        # Auto Fix for Net Melli
                        if "security=tls" in base_config and "allowInsecure" not in base_config:
                             base_config = base_config.replace("?", "?allowInsecure=1&") if "?" in base_config else base_config
                        
                        final_link = f"{base_config}#{safe_name}"
                        valid_configs.append(final_link)
    except Exception as e:
        print(f"Error fetching: {e}")
        return

    # --- Create Subscription Content ---
    if valid_configs:
        # Join all configs with newline
        plain_text = "\n".join(valid_configs)
        # Convert to Base64 (Standard Subscription Format)
        base64_content = base64.b64encode(plain_text.encode("utf-8")).decode("utf-8")
        
        # Check if changed
        try:
            with open("sub.txt", "r") as f:
                old_content = f.read().strip()
        except FileNotFoundError:
            old_content = ""

        if base64_content != old_content:
            print("Updates found! Writing new sub.txt...")
            with open("sub.txt", "w") as f:
                f.write(base64_content)
        else:
            print("No changes detected.")
    else:
        print("No valid configs found.")

if __name__ == "__main__":
    fetch_and_process()
