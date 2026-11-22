import multiprocessing

if __name__ == "__main__":
    multiprocessing.freeze_support()

import os
import sys
import threading
import time
import json
import customtkinter as ctk
import psutil

try:
    import llama_advisor
    HAS_ADVISOR = True
except ImportError:
    HAS_ADVISOR = False

USER_FRIENDLY_ACTIONS = {
    "NEVER_SHARE_OTP": "Do not share this OTP with anyone (even 'customer support'). Scammers use this to approve transactions on your behalf.",
    "REJECT_UPI_COLLECT": "Decline the UPI request immediately. Remember: You never need to enter a UPI PIN to *receive* money.",
    "BLOCK_SENDER_AND_LINK": "Do not click any links. Block the sender and delete the message immediately.",
    "VERIFY_IF_INITIATED_BY_YOU": "If you did not initiate this transaction, contact your bank's official toll-free number immediately.",
    "BLOCK_DOMAIN": "Do not visit this website or enter any credentials. Close the tab immediately.",
    "BLOCK_DOMAIN & WARN_USER": "Do not click the link or provide any personal details. Block the sender and delete the message.",
    "NO_ACTION": "No action needed. You can safely proceed or keep this message for your records.",
    "QUARANTINE_DEVICE": "Disconnect this device from the network immediately to prevent data theft.",
    "BLOCK_SOURCE_IP": "Block the attacking IP address in your firewall settings."
}

def read_soc_temp():
    for zone in ("thermal_zone1", "thermal_zone0"):
        path = f"/sys/devices/virtual/thermal/{zone}/temp"
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    return round(int(f.read().strip()) / 1000.0, 1)
            except Exception:
                pass
    return None

class AegisDesktopWidget(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        ctk.set_widget_scaling(1.3)
        ctk.set_window_scaling(1.3)

        self.title("AEGIS EDGE Guardian")
        self.geometry("1050x650")
        self.minsize(950, 600)

        self.advisor = llama_advisor.LlamaSecurityAdvisor() if HAS_ADVISOR else None
        self.is_generating = False
        self.net_io_last = psutil.net_io_counters()
        self.last_time = time.time()

        self.setup_ui()
        self.update_telemetry()

    def setup_ui(self):
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=5)

        self.tab_monitor = self.tabview.add("Live Monitor")
        self.tab_inbox = self.tabview.add("Scam Simulator")

        # TAB 1: LIVE MONITOR
        self.lbl_status = ctk.CTkLabel(self.tab_monitor, text="SYSTEM SECURE", font=("Helvetica", 24, "bold"), text_color="#2ecc71")
        self.lbl_status.pack(pady=18)

        self.lbl_net = ctk.CTkLabel(self.tab_monitor, text="UL: 0.0 KB/s | DL: 0.0 KB/s", font=("Consolas", 15))
        self.lbl_net.pack()

        self.lbl_hw = ctk.CTkLabel(self.tab_monitor, text="CPU: 0% | RAM: 0%", font=("Consolas", 14), text_color="gray")
        self.lbl_hw.pack(pady=5)

        self.txt_alert = ctk.CTkTextbox(self.tab_monitor, height=200, font=("Helvetica", 15), text_color="#e74c3c", wrap="word")

        self.btn_sim_net = ctk.CTkButton(self.tab_monitor, text="Simulate Network Attack", font=("Helvetica", 14), command=self.trigger_network_alert, fg_color="#34495e")
        self.btn_sim_net.pack(side="bottom", pady=15)

        # TAB 2: INBOX SCAM SIMULATOR
        self.tab_inbox.grid_columnconfigure(0, weight=1)
        self.tab_inbox.grid_columnconfigure(1, weight=2)
        self.tab_inbox.grid_rowconfigure(0, weight=1)

        self.frame_left = ctk.CTkFrame(self.tab_inbox, fg_color="transparent")
        self.frame_left.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        self.frame_controls = ctk.CTkFrame(self.frame_left)
        self.frame_controls.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(self.frame_controls, text="Select or Paste Message", font=("Helvetica", 15, "bold")).pack(pady=6)

        self.btn_scam1 = ctk.CTkButton(self.frame_controls, text="Bank OTP Trap", anchor="w", font=("Helvetica", 14), fg_color="#2c3e50",
                                       command=lambda: self.run_analysis("URGENT: Suspicious txn of Rs 49,999 on HDFC Card. Share 6-digit OTP to cancel."))
        self.btn_scam1.pack(fill="x", padx=10, pady=3)

        self.btn_scam2 = ctk.CTkButton(self.frame_controls, text="Phishing Link", anchor="w", font=("Helvetica", 14), fg_color="#2c3e50",
                                       command=lambda: self.run_analysis("Vi User, KYC pending. Calls stop tonight. Update via: http://vi-sim-update.com"))
        self.btn_scam2.pack(fill="x", padx=10, pady=3)

        self.btn_legit = ctk.CTkButton(self.frame_controls, text="Genuine Alert", anchor="w", font=("Helvetica", 14), fg_color="#2c3e50",
                                       command=lambda: self.run_analysis("Rs.12,500 credited to A/c XXXXXX9802. Avail Bal: Rs 84,230. Download YONO SBI."))
        self.btn_legit.pack(fill="x", padx=10, pady=3)

        self.txt_custom_input = ctk.CTkTextbox(self.frame_controls, height=60, font=("Helvetica", 13), wrap="word")
        self.txt_custom_input.pack(fill="x", padx=10, pady=(8, 4))
        self.txt_custom_input.insert("1.0", "Or paste custom message here...")
        self.txt_custom_input.bind("<FocusIn>", lambda e: self.txt_custom_input.delete("1.0", "end") if "paste custom" in self.txt_custom_input.get("1.0", "end") else None)

        self.btn_custom = ctk.CTkButton(self.frame_controls, text="Analyze Custom", font=("Helvetica", 14), command=self.analyze_custom_text)
        self.btn_custom.pack(fill="x", padx=10, pady=(0, 8))

        self.frame_inbox = ctk.CTkFrame(self.frame_left, fg_color="#1a1a1a")
        self.frame_inbox.pack(fill="both", expand=True)

        ctk.CTkLabel(self.frame_inbox, text="Active Inbox", font=("Helvetica", 14, "bold"), text_color="gray").pack(pady=4)

        self.bubble_frame = ctk.CTkFrame(self.frame_inbox, fg_color="#27ae60", corner_radius=12)
        self.lbl_active_msg = ctk.CTkLabel(self.bubble_frame, text="", font=("Helvetica", 13), text_color="white", justify="left", wraplength=240)
        self.lbl_active_msg.pack(padx=12, pady=10)

        # RIGHT PANEL
        self.frame_right = ctk.CTkFrame(self.tab_inbox, fg_color="#1e1e1e")
        self.frame_right.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        self.frame_right.grid_columnconfigure(0, weight=1)
        self.frame_right.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(self.frame_right, text="Instant Sensor Verdict", font=("Helvetica", 15, "bold")).grid(row=0, column=0, sticky="w", padx=15, pady=(12, 0))
        self.lbl_fast_verdict = ctk.CTkLabel(self.frame_right, text="Waiting for input...", font=("Helvetica", 16, "bold"), text_color="#3498db", justify="left")
        self.lbl_fast_verdict.grid(row=1, column=0, sticky="w", padx=15, pady=4)

        ctk.CTkLabel(self.frame_right, text="Offline Llama-3.2 Advisory", font=("Helvetica", 15, "bold")).grid(row=2, column=0, sticky="w", padx=15, pady=(8, 0))

        self.txt_llama_output = ctk.CTkTextbox(self.frame_right, font=("Helvetica", 14), wrap="word", fg_color="#2b2b2b")
        self.txt_llama_output.grid(row=3, column=0, sticky="nsew", padx=15, pady=(4, 8))

        self.lbl_advice_title = ctk.CTkLabel(self.frame_right, text="Recommended Action", font=("Helvetica", 15, "bold"), text_color="white")
        self.lbl_advice_title.grid(row=4, column=0, sticky="w", padx=15, pady=(4, 0))

        self.txt_system_advice = ctk.CTkTextbox(self.frame_right, font=("Helvetica", 14, "bold"), wrap="word", fg_color="#2c3e50", text_color="#ecf0f1", height=68)
        self.txt_system_advice.grid(row=5, column=0, sticky="ew", padx=15, pady=(4, 12))

    def _set_buttons_state(self, state):
        for btn in (self.btn_scam1, self.btn_scam2, self.btn_legit, self.btn_custom, self.btn_sim_net):
            btn.configure(state=state)

    def update_telemetry(self):
        now = time.time()
        dt = max(now - self.last_time, 0.1)
        net_io_now = psutil.net_io_counters()

        ul_speed = (net_io_now.bytes_sent - self.net_io_last.bytes_sent) / dt / 1024
        dl_speed = (net_io_now.bytes_recv - self.net_io_last.bytes_recv) / dt / 1024

        self.net_io_last = net_io_now
        self.last_time = now

        self.lbl_net.configure(text=f"UL: {ul_speed:.1f} KB/s | DL: {dl_speed:.1f} KB/s")

        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        temp = read_soc_temp()
        hw_text = f"CPU: {cpu}% | RAM: {ram}%" + (f" | SoC Temp: {temp}°C" if temp is not None else "")
        self.lbl_hw.configure(text=hw_text)

        self.after(1500, self.update_telemetry)

    def trigger_network_alert(self):
        if self.is_generating:
            return
        self.is_generating = True
        self._set_buttons_state("disabled")

        self.txt_alert.pack(fill="both", expand=True, padx=15, pady=5)
        self.lbl_status.configure(text="THREAT DETECTED", text_color="#e74c3c")
        self.btn_sim_net.pack_forget()

        self.txt_alert.delete("1.0", "end")
        self.txt_alert.insert("end", "[FAST SENSOR] High-Entropy DNS Exfiltration Detected!\nGenerating plain-English advisory via quantized Llama-3.2-1B (sub-5s)...\n\n")

        if self.advisor:
            threading.Thread(target=self._run_llama_net, daemon=True).start()

    def _run_llama_net(self):
        alert = json.dumps(llama_advisor.SAMPLE_NETWORK_ALERT)
        result = self.advisor.analyze_and_explain(alert)
        clean_text = result["explanation"].replace("**", "")
        self.after(0, self._finish_net_ui, clean_text, result["inference_time_s"])

    def _finish_net_ui(self, clean_text, elapsed):
        self.txt_alert.insert("end", f"Llama Advisory ({elapsed}s):\n\n{clean_text}")
        self.is_generating = False
        self._set_buttons_state("normal")

    def analyze_custom_text(self):
        text = self.txt_custom_input.get("1.0", "end").strip()
        if text and "paste custom message" not in text.lower():
            self.txt_custom_input.delete("1.0", "end")
            self.run_analysis(text)

    def run_analysis(self, text):
        if self.is_generating:
            return
        self.lbl_active_msg.configure(text=text)
        self.bubble_frame.pack(padx=10, pady=8, anchor="w", fill="x")

        self.lbl_fast_verdict.configure(text="Analyzing...", text_color="#f1c40f")
        self.txt_llama_output.delete("1.0", "end")
        self.txt_llama_output.insert("end", "Fast sensors complete. Quantized Llama-3.2-1B generating plain-English advisory (sub-5s)...")
        self.txt_system_advice.delete("1.0", "end")
        self.txt_system_advice.insert("end", "Awaiting sensor resolution...")

        if self.advisor:
            self.is_generating = True
            self._set_buttons_state("disabled")
            report = self.advisor.sensors.analyze_input(text)
            color = "#e74c3c" if report["is_threat"] else "#2ecc71"
            clean_verdict = report["verdict"].replace("_", " ")

            self.lbl_fast_verdict.configure(
                text=f"{clean_verdict} ({report['sensor_latency_ms']} ms) — Confidence: {report['confidence']}",
                text_color=color
            )
            threading.Thread(target=self._run_llama_bg, args=(report,), daemon=True).start()

    def _run_llama_bg(self, report):
        result = self.advisor.explain_report(report)
        raw_text = result["explanation"].replace("**", "")
        lines = [line.strip() for line in raw_text.split("\n")]
        clean_llama_text = "\n".join([line for line in lines if line])

        raw_action = report.get("recommended_action", "NO_ACTION")
        user_advice = USER_FRIENDLY_ACTIONS.get(raw_action, raw_action.replace("_", " ").title())
        self.after(0, self._finish_analysis_ui, clean_llama_text, result["inference_time_s"], user_advice)

    def _finish_analysis_ui(self, clean_llama_text, elapsed, user_advice):
        self.txt_llama_output.delete("1.0", "end")
        self.txt_llama_output.insert("end", f"{clean_llama_text}\n\n(Generated locally on ARM CPU in {elapsed}s)")
        self.txt_system_advice.delete("1.0", "end")
        self.txt_system_advice.insert("end", user_advice)
        self.is_generating = False
        self._set_buttons_state("normal")

def main():
    app = AegisDesktopWidget()
    app.mainloop()


if __name__ == "__main__":
    main()
