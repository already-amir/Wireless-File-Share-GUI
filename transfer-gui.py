import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import socket
import os
import threading

# تنظیمات شبکه
PORT = 5001
BUFFER_SIZE = 65536  # قطعات 64 کیلوبایتی
SEPARATOR = "<SEPARATOR>"

def get_local_ip():
    """تابع برای پیدا کردن IP محلی (Local IP) سیستم شما"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # نیازی نیست واقعا متصل شود، فقط برای پیدا کردن مسیر شبکه است
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
        self.root.title("انتقال فایل وایرلس")
        self.root.geometry("500x550")
        self.root.resizable(False, False)
        
        self.selected_files = []
        self.is_receiving = False
        
        self.setup_gui()

    def setup_gui(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # --- بخش گیرنده (Receiver) ---
        recv_frame = tk.LabelFrame(self.root, text=" 📥 بخش گیرنده (Receiver) ", font=("Arial", 11, "bold"), padx=15, pady=15)
        recv_frame.pack(fill="x", padx=20, pady=15)
        
        my_ip = get_local_ip()
        ttk.Label(recv_frame, text=f"IP سیستم شما:  {my_ip}", font=("Arial", 11)).pack(anchor="w", pady=(0, 10))
        
        self.btn_listen = ttk.Button(recv_frame, text="آماده‌سازی برای دریافت فایل", command=self.start_listening)
        self.btn_listen.pack(fill="x", ipady=5)

        # --- بخش فرستنده (Sender) ---
        send_frame = tk.LabelFrame(self.root, text=" 📤 بخش فرستنده (Sender) ", font=("Arial", 11, "bold"), padx=15, pady=15)
        send_frame.pack(fill="x", padx=20, pady=5)
        
        # فیلد IP گیرنده
        ip_frame = tk.Frame(send_frame)
        ip_frame.pack(fill="x", pady=5)
        ttk.Label(ip_frame, text="IP سیستم گیرنده:", font=("Arial", 10)).pack(side="left")
        self.target_ip_entry = ttk.Entry(ip_frame, font=("Arial", 11), width=18)
        self.target_ip_entry.pack(side="right", fill="x", expand=True, padx=(10, 0))
        
        # دکمه انتخاب فایل
        self.btn_browse = ttk.Button(send_frame, text="انتخاب فایل‌ها (Browse)", command=self.browse_files)
        self.btn_browse.pack(fill="x", pady=(15, 5), ipady=5)
        
        self.lbl_selected_files = ttk.Label(send_frame, text="فایلی انتخاب نشده است.", font=("Arial", 9), foreground="gray")
        self.lbl_selected_files.pack(pady=5)
        
        # دکمه ارسال
        self.btn_send = ttk.Button(send_frame, text="ارسال فایل‌ها", command=self.start_sending)
        self.btn_send.pack(fill="x", pady=(5, 0), ipady=8)

        # --- بخش وضعیت و پیشرفت ---
        status_frame = tk.Frame(self.root, padx=20, pady=15)
        status_frame.pack(fill="x")
        
        self.lbl_status = ttk.Label(status_frame, text="وضعیت: آماده", font=("Arial", 10))
        self.lbl_status.pack(anchor="w", pady=(0, 5))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill="x", ipady=3)
        
        self.lbl_percentage = ttk.Label(status_frame, text="0%", font=("Arial", 10))
        self.lbl_percentage.pack(pady=5)

    def update_ui(self, percent, status_text, percentage_text):
        """بروزرسانی امن رابط گرافیکی از طریق Thread های بک‌گراند"""
        self.progress_var.set(percent)
        self.lbl_status.config(text=status_text)
        self.lbl_percentage.config(text=percentage_text)

    def browse_files(self):
        files = filedialog.askopenfilenames(title="فایل‌های خود را انتخاب کنید")
        if files:
            self.selected_files = files
            self.lbl_selected_files.config(text=f"{len(files)} فایل انتخاب شد.", foreground="green")

    def start_listening(self):
        if self.is_receiving:
            return
        self.is_receiving = True
        self.btn_listen.config(state="disabled", text="در حال انتظار برای اتصال...")
        
        # اجرای سرور در یک Thread جداگانه تا برنامه قفل نشود
        thread = threading.Thread(target=self.receive_thread, daemon=True)
        thread.start()

    def receive_thread(self):
        try:
            s = socket.socket()
            s.bind(("0.0.0.0", PORT))
            s.listen(1)
            
            self.root.after(0, self.update_ui, 0, "در حال انتظار برای اتصال فرستنده...", "0%")
            client_socket, address = s.accept()
            self.root.after(0, self.update_ui, 0, f"متصل شد به: {address[0]}", "0%")
            
            # دریافت تعداد کل فایل‌ها
            msg = client_socket.recv(1024).decode()
            cmd, num_files = msg.split(SEPARATOR)
            num_files = int(num_files)
            client_socket.sendall(b"ACK")
            
            for i in range(num_files):
                # دریافت هدر فایل (نام و حجم)
                header = client_socket.recv(1024).decode()
                filename, filesize = header.split(SEPARATOR)
                filesize = int(filesize)
                client_socket.sendall(b"ACK")
                
                status_text = f"در حال دریافت فایل {i+1} از {num_files}: {filename}"
                
                # دریافت قطعه قطعه فایل
                received = 0
                with open(filename, "wb") as f:
                    while received < filesize:
                        # محاسبه مقدار بایتی که باید خوانده شود تا وارد دیتای فایل بعدی نشویم
                        bytes_to_read = min(BUFFER_SIZE, filesize - received)
                        bytes_read = client_socket.recv(bytes_to_read)
                        if not bytes_read: break
                        f.write(bytes_read)
                        received += len(bytes_read)
                        
                        # بروزرسانی نوار پیشرفت
                        percent = (received / filesize) * 100
                        mb_received = received / (1024*1024)
                        mb_total = filesize / (1024*1024)
                        p_text = f"{percent:.1f}%  ({mb_received:.1f} MB / {mb_total:.1f} MB)"
                        self.root.after(0, self.update_ui, percent, status_text, p_text)
                
                # ارسال تاییدیه اتمام این فایل
                client_socket.sendall(b"FILE_DONE")
            
            client_socket.close()
            s.close()
            self.root.after(0, self.update_ui, 100, "✅ تمام فایل‌ها با موفقیت دریافت شدند!", "100%")
            messagebox.showinfo("موفقیت", "دریافت فایل‌ها با موفقیت به اتمام رسید!")
            
        except Exception as e:
            self.root.after(0, self.update_ui, 0, f"❌ خطا: {str(e)}", "0%")
        finally:
            self.is_receiving = False
            self.root.after(0, lambda: self.btn_listen.config(state="normal", text="آماده‌سازی برای دریافت فایل"))

    def start_sending(self):
        target_ip = self.target_ip_entry.get().strip()
        if not target_ip:
            messagebox.showerror("خطا", "لطفاً IP سیستم گیرنده را وارد کنید!")
            return
        if not self.selected_files:
            messagebox.showerror("خطا", "هیچ فایلی برای ارسال انتخاب نشده است!")
            return
            
        self.btn_send.config(state="disabled")
        self.btn_browse.config(state="disabled")
        
        # اجرای فرآیند ارسال در یک Thread جداگانه
        thread = threading.Thread(target=self.send_thread, args=(target_ip,), daemon=True)
        thread.start()

    def send_thread(self, target_ip):
        try:
            self.root.after(0, self.update_ui, 0, "در حال اتصال به گیرنده...", "0%")
            s = socket.socket()
            s.connect((target_ip, PORT))
            
            # ارسال تعداد فایل‌ها
            num_files = len(self.selected_files)
            s.sendall(f"NUM_FILES{SEPARATOR}{num_files}".encode())
            if s.recv(1024).decode() != "ACK": raise Exception("تاییدیه تعداد فایل دریافت نشد")
            
            for i, filepath in enumerate(self.selected_files):
                filesize = os.path.getsize(filepath)
                filename = os.path.basename(filepath)
                
                # ارسال هدر (نام و حجم)
                s.sendall(f"{filename}{SEPARATOR}{filesize}".encode())
                if s.recv(1024).decode() != "ACK": raise Exception("تاییدیه هدر فایل دریافت نشد")
                
                status_text = f"در حال ارسال فایل {i+1} از {num_files}: {filename}"
                
                # ارسال فایل به صورت قطعه قطعه
                sent = 0
                with open(filepath, "rb") as f:
                    while True:
                        bytes_read = f.read(BUFFER_SIZE)
                        if not bytes_read: break
                        s.sendall(bytes_read)
                        sent += len(bytes_read)
                        
                        # بروزرسانی نوار پیشرفت
                        percent = (sent / filesize) * 100
                        mb_sent = sent / (1024*1024)
                        mb_total = filesize / (1024*1024)
                        p_text = f"{percent:.1f}%  ({mb_sent:.1f} MB / {mb_total:.1f} MB)"
                        self.root.after(0, self.update_ui, percent, status_text, p_text)
                
                # انتظار برای تایید دریافت کامل فایل از سمت گیرنده
                if s.recv(1024).decode() != "FILE_DONE": raise Exception("تاییدیه اتمام فایل دریافت نشد")
            
            s.close()
            self.root.after(0, self.update_ui, 100, "✅ تمام فایل‌ها با موفقیت ارسال شدند!", "100%")
            messagebox.showinfo("موفقیت", "ارسال فایل‌ها با موفقیت به اتمام رسید!")
            
        except Exception as e:
            self.root.after(0, self.update_ui, 0, f"❌ خطا در ارسال: {str(e)}", "0%")
            messagebox.showerror("خطای اتصال", "ارتباط برقرار نشد. بررسی کنید گیرنده در حالت انتظار باشد و IP درست وارد شده باشد.")
        finally:
            self.root.after(0, lambda: self.btn_send.config(state="normal"))
            self.root.after(0, lambda: self.btn_browse.config(state="normal"))


if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferApp(root)
    root.mainloop()
