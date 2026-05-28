from __future__ import annotations

from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from xfile.crypto import encrypt_file_data, decrypt_file_data, DecryptionError
from xfile.format import serialize, deserialize, FormatError


AAD = b"xfile-v1"


class XFileApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        self.title("x-file")
        self.geometry("620x430")
        self.resizable(False, False)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.selected_file: Path | None = None

        self.title_label = ctk.CTkLabel(
            self,
            text="x-file — file encryption",
            font=("Arial", 22, "bold"),
        )
        self.title_label.pack(pady=(25, 10))

        self.file_label = ctk.CTkLabel(
            self,
            text="No file selected",
            wraplength=540,
        )
        self.file_label.pack(pady=10)

        self.choose_button = ctk.CTkButton(
            self,
            text="Select file",
            command=self.choose_file,
        )
        self.choose_button.pack(pady=10)

        self.password_entry = ctk.CTkEntry(
            self,
            placeholder_text="Enter password",
            show="*",
            width=360,
        )
        self.password_entry.pack(pady=(10, 6))

        self.repeat_password_entry = ctk.CTkEntry(
            self,
            placeholder_text="Repeat password (encryption only)",
            show="*",
            width=360,
        )
        self.repeat_password_entry.pack(pady=(0, 10))

        self.buttons_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.buttons_frame.pack(pady=18)

        self.encrypt_button = ctk.CTkButton(
            self.buttons_frame,
            text="Encrypt",
            command=self.encrypt_selected_file,
            width=150,
        )
        self.encrypt_button.grid(row=0, column=0, padx=10)

        self.decrypt_button = ctk.CTkButton(
            self.buttons_frame,
            text="Decrypt",
            command=self.decrypt_selected_file,
            width=150,
        )
        self.decrypt_button.grid(row=0, column=1, padx=10)

        self.status_label = ctk.CTkLabel(
            self,
            text="Status: Ready",
            wraplength=540,
        )
        self.status_label.pack(pady=(10, 0))

    def set_status(self, message: str) -> None:
        self.status_label.configure(text=f"Status: {message}")
        self.update_idletasks()

    def choose_file(self) -> None:
        file_path = filedialog.askopenfilename()

        if not file_path:
            self.set_status("File selection canceled.")
            return

        self.selected_file = Path(file_path)
        self.file_label.configure(text=str(self.selected_file))
        self.set_status("File selected.")

    def get_password(self, *, require_confirmation: bool = False) -> str | None:
        password = self.password_entry.get()

        if not password:
            self.set_status("Missing password.")
            messagebox.showwarning("Missing password", "Enter a password.")
            return None

        if require_confirmation:
            repeated_password = self.repeat_password_entry.get()

            if not repeated_password:
                self.set_status("Missing password confirmation.")
                messagebox.showwarning(
                    "Missing password confirmation",
                    "Repeat the password before encryption.",
                )
                return None

            if password != repeated_password:
                self.set_status("Passwords do not match.")
                messagebox.showwarning(
                    "Password mismatch",
                    "The passwords are not identical.",
                )
                return None

        return password

    def ensure_output_file_can_be_created(self, output_path: Path) -> bool:
        if output_path.exists():
            self.set_status("Operation canceled: target file already exists.")
            messagebox.showwarning(
                "File already exists",
                f"The target file already exists:\n{output_path}",
            )
            return False

        return True
    
    def get_available_output_path(self, output_path: Path) -> Path:
        if not output_path.exists():
            return output_path

        parent = output_path.parent
        stem = output_path.stem
        suffix = output_path.suffix

        counter = 1
        while True:
            candidate = parent / f"{stem} ({counter}){suffix}"

            if not candidate.exists():
                return candidate

            counter += 1

    def get_default_decrypted_output_path(self) -> Path:
        if self.selected_file is None:
            raise RuntimeError("No file selected")

        if self.selected_file.name.endswith(".enc"):
            output_name = self.selected_file.name.removesuffix(".enc")
        else:
            output_name = self.selected_file.name + ".decrypted"

        return self.selected_file.with_name(output_name)

    def encrypt_selected_file(self) -> None:
        if self.selected_file is None:
            self.set_status("No file selected.")
            messagebox.showwarning("No file selected", "Select a file first.")
            return

        password = self.get_password(require_confirmation=True)
        if password is None:
            return

        output_path = self.selected_file.with_name(self.selected_file.name + ".enc")
        if not self.ensure_output_file_can_be_created(output_path):
            return

        try:
            self.set_status("Encrypting...")

            plaintext = self.selected_file.read_bytes()
            artifacts = encrypt_file_data(
                plaintext=plaintext,
                password=password,
                aad=AAD,
            )
            encrypted_data = serialize(artifacts)
            output_path.write_bytes(encrypted_data)

            self.set_status("Encryption completed.")
            messagebox.showinfo(
                "Success",
                f"File encrypted successfully:\n{output_path}",
            )

        except Exception as exc:
            self.set_status("Encryption failed.")
            messagebox.showerror(
                "Encryption error",
                f"Could not encrypt the file:\n{exc}",
            )

    def decrypt_selected_file(self) -> None:
        if self.selected_file is None:
            self.set_status("No file selected.")
            messagebox.showwarning("No file selected", "Select an encrypted file first.")
            return

        password = self.get_password(require_confirmation=False)
        if password is None:
            return

        output_path = self.get_available_output_path(
            self.get_default_decrypted_output_path()
        )

        try:
            self.set_status("Decrypting...")

            encrypted_data = self.selected_file.read_bytes()
            artifacts = deserialize(encrypted_data)
            plaintext = decrypt_file_data(
                artifacts=artifacts,
                password=password,
                aad=AAD,
            )
            output_path.write_bytes(plaintext)

            self.set_status("Decryption completed.")
            messagebox.showinfo(
                "Success",
                f"File decrypted successfully:\n{output_path}",
            )

        except DecryptionError:
            self.set_status("Decryption failed.")
            messagebox.showerror(
                "Decryption error",
                "Wrong password or corrupted file.",
            )

        except FormatError as exc:
            self.set_status("Invalid encrypted file format.")
            messagebox.showerror(
                "Format error",
                f"Invalid encrypted file format:\n{exc}",
            )

        except Exception as exc:
            self.set_status("Decryption failed.")
            messagebox.showerror(
                "Decryption error",
                f"Could not decrypt the file:\n{exc}",
            )


def main() -> None:
    app = XFileApp()
    app.mainloop()


if __name__ == "__main__":
    main()