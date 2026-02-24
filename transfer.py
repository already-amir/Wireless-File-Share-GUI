import socket
import os
import argparse
import sys

# تنظیمات پیش‌فرض
PORT = 5001
BUFFER_SIZE = 65536  # ارسال در قطعات 64 کیلوبایتی برای سرعت بیشتر
SEPARATOR = "<SEPARATOR>"

def print_progress(transferred, total):
    """تابع برای نمایش نوار پیشرفت در ترمینال"""
    percent = (transferred / total) * 100
    bar_length = 40
    filled_length = int(bar_length * percent // 100)
    bar = '#' * filled_length + '-' * (bar_length - filled_length)
    
    transferred_mb = transferred / (1024 * 1024)
    total_mb = total / (1024 * 1024)
    
    sys.stdout.write(f"\r[{bar}] {percent:.2f}%  ({transferred_mb:.1f} MB / {total_mb:.1f} MB)")
    sys.stdout.flush()

def start_receiver():
    """حالت گیرنده (سرور)"""
    # ساخت سوکت
    s = socket.socket()
    # بایند کردن به تمام IP های سیستم (0.0.0.0) روی پورت مشخص
    s.bind(("0.0.0.0", PORT))
    s.listen(1)
    
    print(f"[*] Waiting for connection on port {PORT}...")
    client_socket, address = s.accept()
    print(f"[+] Client {address} connected.")

    # دریافت اطلاعات اولیه فایل (نام و حجم)
    received_header = client_socket.recv(BUFFER_SIZE).decode()
    filename, filesize = received_header.split(SEPARATOR)
    filename = os.path.basename(filename)
    filesize = int(filesize)

    # ارسال تاییدیه دریافت هدر به فرستنده
    client_socket.sendall(b"ACK")

    print(f"[*] Receiving file: {filename} ({filesize / (1024*1024):.2f} MB)")

    # دریافت فایل به صورت قطعه قطعه و نوشتن روی هارد
    received_bytes = 0
    with open(filename, "wb") as f:
        while received_bytes < filesize:
            # خواندن دیتا از شبکه
            bytes_read = client_socket.recv(BUFFER_SIZE)
            if not bytes_read:
                break
            # نوشتن دیتا روی فایل
            f.write(bytes_read)
            received_bytes += len(bytes_read)
            # نمایش پیشرفت
            print_progress(received_bytes, filesize)

    print("\n[+] File transfer completed successfully!")
    client_socket.close()
    s.close()

def start_sender(filepath, target_ip):
    """حالت فرستنده (کلاینت)"""
    if not os.path.exists(filepath):
        print(f"[-] Error: File '{filepath}' does not exist.")
        return

    filesize = os.path.getsize(filepath)
    filename = os.path.basename(filepath)

    s = socket.socket()
    print(f"[*] Connecting to {target_ip}:{PORT}...")
    try:
        s.connect((target_ip, PORT))
        print("[+] Connected successfully.")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    # ارسال اطلاعات اولیه فایل
    header = f"{filename}{SEPARATOR}{filesize}"
    s.sendall(header.encode())

    # انتظار برای دریافت تاییدیه از گیرنده
    ack = s.recv(1024).decode()
    if ack != "ACK":
        print("[-] Error: Did not receive acknowledgment from receiver.")
        s.close()
        return

    print(f"[*] Sending file: {filename} ({filesize / (1024*1024):.2f} MB)")

    # خواندن فایل از هارد و ارسال به شبکه
    sent_bytes = 0
    with open(filepath, "rb") as f:
        while True:
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                break
            s.sendall(bytes_read)
            sent_bytes += len(bytes_read)
            # نمایش پیشرفت
            print_progress(sent_bytes, filesize)

    print("\n[+] File sent successfully!")
    s.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wireless File Transfer Script")
    subparsers = parser.add_subparsers(dest="mode", help="Choose mode: receive or send")

    # پارامترهای حالت گیرنده
    receiver_parser = subparsers.add_parser("receive", help="Act as receiver")

    # پارامترهای حالت فرستنده
    sender_parser = subparsers.add_parser("send", help="Act as sender")
    sender_parser.add_argument("filepath", help="Path to the file you want to send")
    sender_parser.add_argument("ip", help="IP address of the receiving PC")

    args = parser.parse_args()

    if args.mode == "receive":
        start_receiver()
    elif args.mode == "send":
        start_sender(args.filepath, args.ip)
    else:
        parser.print_hel   p()
