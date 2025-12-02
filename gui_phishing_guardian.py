import tkinter as tk
from tkinter import ttk, messagebox

from phishing_guardian import PhishingGuardian


class PhishingGuardianGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Phishing Guardian – Analyse Emails & URLs")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)

        self.guardian = PhishingGuardian()

        self._build_style()
        self._build_layout()

    def _build_style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#0f172a")
        style.configure("TLabel", background="#0f172a", foreground="#e5e7eb")
        style.configure(
            "Primary.TButton",
            background="#2563eb",
            foreground="#f9fafb",
            padding=6,
        )
        style.map(
            "Primary.TButton",
            background=[("active", "#1d4ed8")],
        )

    def _build_layout(self) -> None:
        main = ttk.Frame(self.root, padding=16)
        main.pack(fill=tk.BOTH, expand=True)

        # Colonne gauche : saisie
        left = ttk.Frame(main)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        lbl_email = ttk.Label(left, text="Contenu de l'email à analyser :")
        lbl_email.pack(anchor="w")
        self.txt_email = tk.Text(left, height=12, wrap=tk.WORD, bg="#020617", fg="#e5e7eb", insertbackground="#e5e7eb")
        self.txt_email.pack(fill=tk.BOTH, expand=True, pady=(4, 12))

        lbl_urls = ttk.Label(left, text="Liste d'URLs (séparées par des virgules) :")
        lbl_urls.pack(anchor="w")
        self.entry_urls = ttk.Entry(left)
        self.entry_urls.pack(fill=tk.X, pady=(4, 4))

        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill=tk.X, pady=(8, 0))

        self.btn_analyze = ttk.Button(
            btn_frame,
            text="Analyser",
            style="Primary.TButton",
            command=self.on_analyze,
        )
        self.btn_analyze.pack(side=tk.LEFT)

        self.lbl_status = ttk.Label(btn_frame, text="", foreground="#a5b4fc")
        self.lbl_status.pack(side=tk.LEFT, padx=(12, 0))

        # Colonne droite : résultats
        right = ttk.Frame(main)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(8, 0))

        lbl_result = ttk.Label(right, text="Résultats de l'analyse :")
        lbl_result.pack(anchor="w")

        self.txt_result = tk.Text(
            right,
            height=20,
            wrap=tk.WORD,
            state=tk.DISABLED,
            bg="#020617",
            fg="#e5e7eb",
            insertbackground="#e5e7eb",
        )
        self.txt_result.pack(fill=tk.BOTH, expand=True, pady=(4, 4))

    def on_analyze(self) -> None:
        email_text = self.txt_email.get("1.0", tk.END).strip()
        urls_raw = self.entry_urls.get().strip()
        urls = [u.strip() for u in urls_raw.split(",") if u.strip()]

        if not email_text and not urls:
            messagebox.showwarning("Aucun contenu", "Veuillez saisir au moins un email ou une URL.")
            return

        self.lbl_status.config(text="Analyse en cours...")
        self.root.update_idletasks()

        try:
            report = self.guardian.analyze(
                email_text=email_text if email_text else None,
                urls=urls if urls else None,
            )
        except Exception as exc:  # pragma: no cover - simple garde
            self.lbl_status.config(text="")
            messagebox.showerror("Erreur", f"Une erreur s'est produite : {exc}")
            return

        self._display_report(report)

    def _display_report(self, report) -> None:
        self.txt_result.config(state=tk.NORMAL)
        self.txt_result.delete("1.0", tk.END)

        summary = report.risk_summary()
        level = summary["niveau"]
        score = summary["score"]

        header = f"=== Synthèse du risque ===\nNiveau : {level.upper()}  |  Score : {score}\n\n"
        self.txt_result.insert(tk.END, header)

        # Couleur de niveau
        color = "#22c55e"
        if level == "modere":
            color = "#eab308"
        elif level == "eleve":
            color = "#f97316"
        elif level == "critique":
            color = "#ef4444"

        self.txt_result.tag_configure("risk", foreground=color, font=("Segoe UI", 10, "bold"))
        self.txt_result.tag_add("risk", "2.0", "2.end")

        if report.email_result:
            self.txt_result.insert(tk.END, "--- Analyse Email ---\n")
            e = report.email_result
            self.txt_result.insert(tk.END, f"Label : {e['label']}\n")
            self.txt_result.insert(tk.END, f"Score : {e['score']:.3f}\n")
            if e["indicators"]:
                self.txt_result.insert(tk.END, "Indicateurs :\n")
                for ind in e["indicators"]:
                    self.txt_result.insert(tk.END, f"  - {ind}\n")
            self.txt_result.insert(tk.END, f"Modèle : {e['model_used']}\n\n")

        if report.url_results:
            self.txt_result.insert(tk.END, "--- Analyse URLs ---\n")
            for item in report.url_results:
                self.txt_result.insert(tk.END, f"{item['url']}\n")
                self.txt_result.insert(tk.END, f"  Label : {item['label']}  |  Score : {item['score']:.3f}\n")
                if item["indicators"]:
                    self.txt_result.insert(tk.END, "  Indicateurs :\n")
                    for ind in item["indicators"]:
                        self.txt_result.insert(tk.END, f"    - {ind}\n")
                self.txt_result.insert(tk.END, f"  Modèle : {item['model_used']}\n\n")

        self.txt_result.config(state=tk.DISABLED)
        self.lbl_status.config(text="Analyse terminée.")


def main() -> None:
    root = tk.Tk()
    app = PhishingGuardianGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()


