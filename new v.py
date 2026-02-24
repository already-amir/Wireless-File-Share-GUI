import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import socket
import os
import threading
import time

# تنظیمات شبکه بهینه‌شده برای سرعت بالا
PORT = 5001
BUFFER_SIZE = 1024 * 1024 * 4  # افزایش بافر به 4 مگابایت برای سرعت بیشتر در شبکه محلی
SEPARATOR = "<SEPARATOR>"

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

class FileTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("انتقال فایل وایرلس - نسخه پرسرعت")
        self.root.geometry("500x570")
        self.root.resizable(False, False)
        
        self.selected_files = []
        self.is_receiving = False
        
        self.setup_gui()

    def setup_gui(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # --- بخش گیرنده ---
        recv_frame = tk.LabelFrame(self.root, text=" 📥 گیرنده (Receiver) ", font=("Arial", 11, "bold"), padx=15, pady=15)
        recv_frame.pack(fill="x", padx=20, pady=15)
        
        my_ip = get_local_ip()
        ttk.Label(recv_frame, text=f"IP سیستم شما:  {my_ip}", font=("Arial", 11, "bold"), foreground="blue").pack(anchor="w", pady=(0, 10))
        
        self.btn_listen = ttk.Button(recv_frame, text="آماده‌سازی برای دریافت فایل", command=self.start_listening)
        self.btn_listen.pack(fill="x", ipady=5)

        # --- بخش فرستنده ---
        send_frame = tk.LabelFrame(self.root, text=" 📤 فرستنده (Sender) ", font=("Arial", 11, "bold"), padx=15, pady=15)
        send_frame.pack(fill="x", padx=20, pady=5)
        
        ip_frame = tk.Frame(send_frame)
        ip_frame.pack(fill="x", pady=5)
        ttk.Label(ip_frame, text="IP گیرنده:", font=("Arial", 10)).pack(side="left")
        self.target_ip_entry = ttk.Entry(ip_frame, font=("Arial", 11), width=18)
        self.target_ip_entry.pack(side="right", fill="x", expand=True, padx=(10, 0))
        
        self.btn_browse = ttk.Button(send_frame, text="انتخاب فایل‌ها (Browse)", command=self.browse_files)
        self.btn_browse.pack(fill="x", pady=(15, 5), ipady=5)
        
        self.lbl_selected_files = ttk.Label(send_frame, text="فایلی انتخاب نشده است.", font=("Arial", 9), foreground="gray")
        self.lbl_selected_files.pack(pady=5)
        
        self.btn_send = ttk.Button(send_frame, text="ارسال فایل‌ها", command=self.start_sending)
        self.btn_send.pack(fill="x", pady=(5, 0), ipady=8)

        # --- بخش وضعیت، سرعت و پیشرفت ---
        status_frame = tk.Frame(self.root, padx=20, pady=15)
        status_frame.pack(fill="x")
        
        self.lbl_status = ttk.Label(status_frame, text="وضعیت: آماده", font=("Arial", 10))
        self.lbl_status.pack(anchor="w", pady=(0, 5))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill="x", ipady=3)
        
        # فریمی برای نمایش حجم و سرعت در کنار هم
        info_frame = tk.Frame(status_frame)
        info_frame.pack(fill="x", pady=5)
        
        self.lbl_percentage = ttk.Label(info_frame, text="0% (0 MB / 0 MB)", font=("Arial", 9))
        self.lbl_percentage.pack(side="left")
        
        self.lbl_speed = ttk.Label(info_frame, text="سرعت: 0 MB/s", font=("Arial", 9, "bold"), foreground="green")
        self.lbl_speed.pack(side="right")

    def update_ui(self, percent, status_text, percentage_text, speed_text=""):
        self.progress_var.set(percent)
        self.lbl_status.config(text=status_text)
        self.lbl_percentage.config(text=percentage_text)
        if speed_text:
            self.lbl_speed.config(text=speed_text)

    def browse_files(self):
        files = filedialog.askopenfilenames(title="فایل‌های خود را انتخاب کنید")
        if files:
            self.selected_files = files
            self.lbl_selected_files.config(text=f"{len(files)} فایل انتخاب شد.", foreground="green")

    def start_listening(self):
        if self.is_receiving: return
        self.is_receiving = True
        self.btn_listen.config(state="disabled", text="در حال انتظار...")
        threading.Thread(target=self.receive_thread, daemon=True).start()

    def receive_thread(self):
        try:
            s = socket.socket()
            s.bind(("0.0.0.0", PORT))
            s.listen(1)
            
            self.root.after(0, self.update_ui, 0, "منتظر فرستنده...", "0%", "سرعت: 0 MB/s")
            client_socket, address = s.accept()
            self.root.after(0, self.update_ui, 0, f"متصل شد: {address[0]}", "0%", "سرعت: محاسبه...")
            
            msg = client_socket.recv(1024).decode()
            cmd, num_files = msg.split(SEPARATOR)
            num_files = int(num_files)
            client_socket.sendall(b"ACK")
            
            for i in range(num_files):
                header = client_socket.recv(1024).decode()
                filename, filesize = header.split(SEPARATOR)
                filesize = int(filesize)
                client_socket.sendall(b"ACK")
                
                status_text = f"دریافت فایل {i+1}/{num_files}: {filename}"
                
                received = 0
                last_update_time = time.time()
                bytes_since_update = 0
                
                with open(filename, "wb") as f:
                    while received < filesize:
                        bytes_to_read = min(BUFFER_SIZE, filesize - received)
                        chunk = client_socket.recv(bytes_to_read)
                        if not chunk: break
                        
                        f.write(chunk)
                        chunk_len = len(chunk)
                        received += chunk_len
                        bytes_since_update += chunk_len
                        
                        current_time = time.time()
                        time_diff = current_time - last_update_time
                        
                        # بروزرسانی گرافیک فقط هر 0.2 ثانیه یکبار (جلوگیری از هنگ کردن و افت سرعت)
                        if time_diff >= 0.2:
                            speed_bps = bytes_since_update / time_diff
                            speed_mbps = speed_bps / (1024 * 1024)
                            
                            percent = (received / filesize) * 100
                            mb_received = received / (1024*1024)
                            mb_total = filesize / (1024*1024)
                            
                            p_text = f"{percent:.1f}%  ({mb_received:.1f} / {mb_total:.1f} MB)"
                            s_text = f"سرعت: {speed_mbps:.1f} MB/s"
                            
                            self.root.after(0, self.update_ui, percent, status_text, p_text, s_text)
                            
                            last_update_time = current_time
                            bytes_since_update = 0
                            
                client_socket.sendall(b"FILE_DONE")
            
            client_socket.close()
            s.close()
            self.root.after(0, self.update_ui, 100, "✅ دریافت موفق!", "100%", "پایان یافت")
            messagebox.showinfo("موفقیت", "دریافت فایل‌ها تمام شد!")
            
        except Exception as e:
            self.root.after(0, self.update_ui, 0, f"❌ خطا: {str(e)}", "0%", "")
        finally:
            self.is_receiving = False
            self.root.after(0, lambda: self.btn_listen.config(state="normal", text="آماده‌سازی برای دریافت فایل"))

    def start_sending(self):
        target_ip = self.target_ip_entry.get().strip()
        if not target_ip:
            messagebox.showerror("خطا", "IP گیرنده را وارد کنید!")
            return
        if not self.selected_files:
            messagebox.showerror("خطا", "فایلی انتخاب نشده است!")
            return
            
        self.btn_send.config(state="disabled")
        self.btn_browse.config(state="disabled")
        threading.Thread(target=self.send_thread, args=(target_ip,), daemon=True).start()

    def send_thread(self, target_ip):
        try:
            self.root.after(0, self.update_ui, 0, "در حال اتصال...", "0%", "سرعت: 0 MB/s")
            s = socket.socket()
            s.connect((target_ip, PORT))
            
            num_files = len(self.selected_files)
            s.sendall(f"NUM_FILES{SEPARATOR}{num_files}".encode())
            if s.recv(1024).decode() != "ACK": raise Exception("تاییدیه دریافت نشد")
            
            for i, filepath in enumerate(self.selected_files):
                filesize = os.path.getsize(filepath)
                filename = os.path.basename(filepath)
                
                s.sendall(f"{filename}{SEPARATOR}{filesize}".encode())
                if s.recv(1024).decode() != "ACK": raise Exception("تاییدیه فایل دریافت نشد")
                
                status_text = f"ارسال فایل {i+1}/{num_files}: {filename}"
                
                sent = 0
                last_update_time = time.time()
                bytes_since_update = 0
                
                with open(filepath, "rb") as f:
                    while True:
                        chunk = f.read(BUFFER_SIZE)
                        if not chunk: break
                        
                        s.sendall(chunk)
                        chunk_len = len(chunk)
                        sent += chunk_len
                        bytes_since_update += chunk_len
                        
                        current_time = time.time()
                        time_diff = current_time - last_update_time
                        
                        # بروزرسانی گرافیک فقط هر 0.2 ثانیه یکبار
                        if time_diff >= 0.2:
                            speed_bps = bytes_since_update / time_diff
                            speed_mbps = speed_bps / (1024 * 1024)
                            
                            percent = (sent / filesize) * 100
                            mb_sent = sent / (1024*1024)
                            mb_total = filesize / (1024*1024)
                            
                            p_text = f"{percent:.1f}%  ({mb_sent:.1f} / {mb_total:.1f} MB)"
                            s_text = f"سرعت: {speed_mbps:.1f} MB/s"
                            
                            self.root.after(0, self.update_ui, percent, status_text, p_text, s_text)
                            
                            last_update_time = current_time
                            bytes_since_update = 0
                            
                if s.recv(1024).decode() != "FILE_DONE": raise Exception("تاییدیه اتمام دریافت نشد")
            
            s.close()
            self.root.after(0, self.update_ui, 100, "✅ ارسال موفق!", "100%", "پایان یافت")
            messagebox.showinfo("موفقیت", "ارسال تمام شد!")
            
        except Exception as e:
            self.root.after(0, self.update_ui, 0, f"❌ خطا: {str(e)}", "0%", "")
            messagebox.showerror("خطا", "ارتباط قطع شد یا IP اشتباه است.")
        finally:
            self.root.after(0, lambda: self.btn_send.config(state="normal"))
            self.root.after(0, lambda: self.btn_browse.config(state="normal"))


if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferApp(root)
    root.mainloop()
