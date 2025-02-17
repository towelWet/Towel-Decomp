import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess, os, threading, queue, time, sys

class GhidraDecompilerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Ghidra Binary Decompiler")
        self.root.geometry("800x600")
        
        # Configure paths
        self.ghidra_path = r"C:\RE\Ghidra\support\analyzeHeadless.bat"
        self.project_path = r"C:\RE\Ghidra\Projects"
        self.project_name = "DecompilerProject"
        self.script_path = r"C:\Users\Towel\Downloads\toweldecomp"  # Folder with DecompileAll.java
        
        # Process tracking
        self.current_process = None
        self.decompile_thread = None
        self.queue = queue.Queue()
        
        self.setup_ui()
        self.check_queue()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        ttk.Label(main_frame, text="Input Binary File:").grid(row=0, column=0, sticky="w", pady=5)
        self.input_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.input_var, width=70).grid(row=1, column=0, padx=5, sticky="we")
        ttk.Button(main_frame, text="Browse", command=self.browse_input).grid(row=1, column=1, padx=5)
        
        ttk.Label(main_frame, text="Output Directory:").grid(row=2, column=0, sticky="w", pady=5)
        self.output_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.output_var, width=70).grid(row=3, column=0, padx=5, sticky="we")
        ttk.Button(main_frame, text="Browse", command=self.browse_output).grid(row=3, column=1, padx=5)
        
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="5")
        status_frame.grid(row=4, column=0, columnspan=2, pady=10, sticky="we")
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate', length=300)
        self.progress.grid(row=1, column=0, pady=5, sticky="we")
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=5)
        self.decompile_button = ttk.Button(button_frame, text="Decompile", command=self.start_decompilation)
        self.decompile_button.pack(side="left", padx=5)
        self.cancel_button = ttk.Button(button_frame, text="Cancel", command=self.cancel_decompilation, state='disabled')
        self.cancel_button.pack(side="left", padx=5)
        
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="5")
        log_frame.grid(row=6, column=0, columnspan=2, pady=5, sticky="nsew")
        self.log_text = tk.Text(log_frame, height=15, width=80, wrap="word")
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_text['yscrollcommand'] = scrollbar.set
        
        main_frame.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
    
    def browse_input(self):
        filename = filedialog.askopenfilename(
            title="Select Binary File",
            filetypes=[("VST3 Plugin", "*.vst3"), ("Dynamic Link Library", "*.dll"), ("Executable", "*.exe"), ("All files", "*.*")]
        )
        if filename:
            self.input_var.set(filename)
    
    def browse_output(self):
        directory = filedialog.askdirectory(title="Select Output Directory")
        if directory:
            self.output_var.set(directory)
    
    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()
    
    def start_decompilation(self):
        if not self.input_var.get() or not self.output_var.get():
            messagebox.showerror("Error", "Please select both input file and output directory.")
            return
        if not os.path.exists(self.ghidra_path):
            messagebox.showerror("Error", "Ghidra headless analyzer not found.")
            return
        
        self.decompile_button.config(state='disabled')
        self.cancel_button.config(state='normal')
        self.progress.start(10)
        self.status_var.set("Decompiling...")
        
        self.decompile_thread = threading.Thread(target=self.run_decompilation)
        self.decompile_thread.daemon = True
        self.decompile_thread.start()
    
    def run_decompilation(self):
        try:
            input_file = self.input_var.get()
            output_dir = self.output_var.get()
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(output_dir, f"decompiled_{timestamp}.txt")
            
            if not os.path.exists(self.project_path):
                os.makedirs(self.project_path)
            
            # Removed the "-noanalysis" flag to run full analysis.
            command = [
                self.ghidra_path,
                self.project_path,
                self.project_name,
                "-import", input_file,
                "-scriptPath", self.script_path,
                "-postScript", "DecompileAll.java", output_file,
                "-deleteProject",
                "-overwrite"
            ]
            
            self.queue.put(("log", "Starting decompilation of: " + input_file))
            self.queue.put(("log", "Command: " + " ".join(command)))
            
            self.current_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
            )
            
            while True:
                line = self.current_process.stdout.readline()
                if not line and self.current_process.poll() is not None:
                    break
                if line:
                    self.queue.put(("log", line.strip()))
            
            rc = self.current_process.poll()
            if rc == 0:
                self.queue.put(("success", f"Decompilation completed. Output saved to: {output_file}"))
            else:
                stderr = self.current_process.stderr.read()
                self.queue.put(("error", f"Decompilation failed. Error:\n{stderr}"))
        except Exception as e:
            self.queue.put(("error", f"Error during decompilation: {str(e)}"))
        finally:
            self.current_process = None
    
    def cancel_decompilation(self):
        if self.current_process:
            if sys.platform == 'win32':
                subprocess.call(['taskkill', '/F', '/T', '/PID', str(self.current_process.pid)])
            else:
                self.current_process.terminate()
            self.queue.put(("cancelled", "Decompilation cancelled by user"))
    
    def check_queue(self):
        try:
            while True:
                msg_type, message = self.queue.get_nowait()
                if msg_type == "log":
                    self.log(message)
                elif msg_type == "error":
                    self.progress.stop()
                    self.status_var.set("Error")
                    self.decompile_button.config(state='normal')
                    self.cancel_button.config(state='disabled')
                    messagebox.showerror("Error", message)
                elif msg_type == "success":
                    self.progress.stop()
                    self.status_var.set("Completed")
                    self.decompile_button.config(state='normal')
                    self.cancel_button.config(state='disabled')
                    messagebox.showinfo("Success", message)
                elif msg_type == "cancelled":
                    self.progress.stop()
                    self.status_var.set("Cancelled")
                    self.decompile_button.config(state='normal')
                    self.cancel_button.config(state='disabled')
                    self.log("Decompilation cancelled.")
                self.queue.task_done()
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.check_queue)
    
    def on_closing(self):
        if self.current_process:
            if messagebox.askokcancel("Quit", "Decompilation is in progress. Cancel and quit?"):
                self.cancel_decompilation()
                self.root.destroy()
        else:
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = GhidraDecompilerGUI(root)
    root.mainloop()
