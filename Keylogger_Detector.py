import tkinter as tk
from tkinter import ttk, messagebox
import psutil

class KeyloggerDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Keylogger Detector")
        self.root.geometry("700x500")
        self.root.configure(bg="#f0f0f0")
        self.create_ui()

    def create_ui(self):
        # Title
        title = tk.Label(
            self.root,
            text="Keylogger Detector",
            font=("Ubuntu", 20, "bold"),
            bg="#f0f0f0"
        )
        title.pack(pady=15)

        # Scan Button
        scan_button = tk.Button(
            self.root,
            text="Scan for Suspicious Processes",
            font=("Ubuntu", 12),
            bg="#4CAF50",
            fg="white",
            padx=10,
            pady=5,
            command=self.scan_processes
        )
        scan_button.pack(pady=10)

        # Treeview for results
        frame = tk.Frame(self.root)
        frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.tree = ttk.Treeview(frame, columns=("PID", "Process Name"), show="headings", height=15)
        self.tree.heading("PID", text="PID")
        self.tree.heading("Process Name", text="Process Name")
        self.tree.column("PID", width=100)
        self.tree.column("Process Name", width=500)

        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        # Status Label
        self.status_label = tk.Label(
            self.root,
            text="Ready",
            font=("Ubuntu", 10),
            bg="#f0f0f0",
            fg="gray"
        )
        self.status_label.pack(pady=5)

    def scan_processes(self):
        self.tree.delete(*self.tree.get_children())
        keywords = ['keylog', 'hook', 'logger', 'spy', 'capture', 'pynput']
        suspicious = []

        self.status_label.config(text="Scanning...")

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pname = proc.info['name'].lower()
                cmdline = ' '.join(proc.info['cmdline']).lower()  # Includes script name

                if any(kw in pname or kw in cmdline for kw in keywords):
                    suspicious.append((proc.info['pid'], pname + " - " + cmdline))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
               continue

        if suspicious:
            for pid, name in suspicious:
                self.tree.insert("", "end", values=(pid, name))
            messagebox.showwarning("Alert", f"{len(suspicious)} suspicious process(es) found!")
            self.status_label.config(text="Scan Complete: Suspicious Processes Found")
        else:
            messagebox.showinfo("All Clear", "No suspicious processes found.")
            self.status_label.config(text="Scan Complete: No Suspicious Processes")

if __name__ == "__main__":
    root = tk.Tk()
    app = KeyloggerDetectorApp(root)
    root.mainloop()
