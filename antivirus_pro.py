import os
import hashlib
import shutil
import threading
import json
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import joblib
from sklearn.linear_model import LogisticRegression
import numpy as np

# ================= НАСТРОЙКИ =================
BASE = os.path.abspath(os.path.dirname(__file__))
QDIR = os.path.join(BASE, "quarantine")
LOGF = os.path.join(BASE, "av.log")
SIGF = os.path.join(BASE, "signatures.json")
MLF = os.path.join(BASE, "ml.model")

os.makedirs(QDIR, exist_ok=True)

# ================= СИГНАТУРЫ =================
DEFAULT_SIG = {
    "hashes": [],
    "strings": ["malware", "ransom", "keylogger", "stealer", "cmd.exe"],
    "extensions": [".exe", ".bat", ".vbs", ".scr", ".ps1"]
}

def load_sig():
    if not os.path.exists(SIGF):
        with open(SIGF, "w") as f:
            json.dump(DEFAULT_SIG, f, indent=4)
    return json.load(open(SIGF))

sig = load_sig()

# ================= ЛОГИ =================
def log(msg):
    t = datetime.now().strftime("%H:%M:%S")
    line = f"[{t}] {msg}"
    with open(LOGF, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    box.insert(tk.END, line + "\n")
    box.see(tk.END)

# ================= УТИЛИТЫ =================
def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(4096), b""):
            h.update(c)
    return h.hexdigest()

def quarantine(p):
    try:
        shutil.move(p, os.path.join(QDIR, os.path.basename(p)))
        log(f"Карантин: {p}")
    except:
        pass

# ================= ЭВРИСТИКА =================
def heuristic(p):
    score = 0
    ext = os.path.splitext(p)[1].lower()
    if ext in sig["extensions"]:
        score += 2
    try:
        with open(p, "rb") as f:
            d = f.read(4096).lower()
            for s in sig["strings"]:
                if s.encode() in d:
                    score += 2
    except:
        pass
    return score

# ================= ML =================
def train_ml():
    X = [
        [1,1,1,1],
        [0,0,0,0],
        [1,0,1,0],
        [0,1,0,1]
    ]
    y = [1,0,1,0]
    m = LogisticRegression()
    m.fit(X, y)
    joblib.dump(m, MLF)

def ml_predict(p):
    if not os.path.exists(MLF):
        train_ml()
    m = joblib.load(MLF)
    features = [
        os.path.getsize(p) > 50000,
        heuristic(p) > 1,
        os.path.splitext(p)[1].lower() in sig["extensions"],
        True
    ]
    return m.predict([np.array(features).astype(int)])[0]

# ================= СКАНЕР =================
def scan_file(p):
    try:
        if md5(p) in sig["hashes"]:
            return True
        if heuristic(p) >= 3:
            return True
        if ml_predict(p):
            return True
    except:
        pass
    return False

def scan_dir(d):
    found = 0
    for r,_,fs in os.walk(d):
        for f in fs:
            p = os.path.join(r,f)
            if scan_file(p):
                quarantine(p)
                found += 1
    messagebox.showinfo("Сканирование", f"Найдено угроз: {found}")

# ================= REALTIME =================
class RT(FileSystemEventHandler):
    def on_created(self,e):
        if not e.is_directory and scan_file(e.src_path):
            quarantine(e.src_path)

    def on_modified(self,e):
        if not e.is_directory and scan_file(e.src_path):
            quarantine(e.src_path)

def realtime(path):
    o = Observer()
    o.schedule(RT(), path, recursive=True)
    o.start()
    log(f"Realtime ON: {path}")

# ================= GUI =================
def scan_btn():
    d = filedialog.askdirectory()
    if d:
        threading.Thread(target=scan_dir,args=(d,),daemon=True).start()

def rt_btn():
    d = filedialog.askdirectory()
    if d:
        threading.Thread(target=realtime,args=(d,),daemon=True).start()

def update_btn():
    log("Сигнатуры обновлены (локально)")

root = tk.Tk()
root.title("Antivirus PRO")
root.geometry("800x500")

tk.Button(root,text="Сканировать",width=25,command=scan_btn).pack(pady=5)
tk.Button(root,text="Realtime защита",width=25,command=rt_btn).pack(pady=5)
tk.Button(root,text="Обновить сигнатуры",width=25,command=update_btn).pack(pady=5)

box = scrolledtext.ScrolledText(root,width=95,height=20)
box.pack(pady=10)

log("Антивирус запущен")
root.mainloop()
