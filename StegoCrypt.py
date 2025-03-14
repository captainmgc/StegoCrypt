#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
StegoCrypt - Gelişmiş Steganografi Aracı
Geliştirici: CaptainMGC (github.com/captainmgc)
"""

import os
import sys
import numpy as np
import cv2
from PIL import Image
from datetime import datetime
import binascii
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import base64
from PIL import Image, ImageTk
import webbrowser

class SteganographyTool:
    def __init__(self):
        # Desteklenen formatları genişletiyoruz
        self.supported_formats = ['.png', '.bmp', '.jpg', '.jpeg', '.tiff', '.gif', '.webp']
        self.header_size = 64  # Mesaj uzunluğu ve diğer meta verileri saklamak için

    def validate_image(self, image_path):
        """Görüntünün desteklenen bir formatta olup olmadığını kontrol eder."""
        _, ext = os.path.splitext(image_path.lower())
        if ext not in self.supported_formats:
            raise ValueError(f"Desteklenmeyen dosya formatı: {ext}. Desteklenen formatlar: {', '.join(self.supported_formats)}")

        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Dosya bulunamadı: {image_path}")

        return True

    def calculate_capacity(self, image_path):
        """Görüntünün maksimum kapasitesini hesaplar."""
        img = np.array(Image.open(image_path))
        # RGB kanalları için daha hızlı hesaplama
        return (img.size * 3) // 8 - self.header_size

    def text_to_binary(self, text):
        """Metni ikili (binary) formata dönüştürür."""
        binary = ''.join(format(ord(char), '08b') for char in text)
        return binary

    def binary_to_text(self, binary):
        """İkili (binary) formatı metne dönüştürür."""
        text = ''
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            text += chr(int(byte, 2))
        return text

    def embed_data(self, image_path, message, output_path, encryption=None, key=None):
        """Veriyi görüntüye gizler."""
        self.validate_image(image_path)

        # Mesajı hazırla
        if encryption == 'aes':
            message = self._encrypt_aes(message, key)
        elif encryption == 'rsa':
            message = self._encrypt_rsa(message, key)

        metadata = {
            'timestamp': datetime.now().isoformat(),
            'encryption': encryption or 'none',
            'length': len(message)
        }

        metadata_json = json.dumps(metadata)
        message_with_metadata = f"{metadata_json}|{message}"

        capacity = self.calculate_capacity(image_path)
        if len(message_with_metadata) > capacity:
            raise ValueError(f"Mesaj çok uzun. Maksimum kapasite: {capacity} karakter")

        # Görüntüyü aç
        img = Image.open(image_path)
        width, height = img.size
        img_array = np.array(img)

        # Metni ikili formata dönüştür
        binary_message = self.text_to_binary(message_with_metadata)

        # Mesajı yerleştir
        data_index = 0
        modified = False

        for i in range(height):
            for j in range(width):
                pixel = img_array[i, j]

                # Her pikselin her renk kanalında LSB'yi değiştir
                for color_channel in range(min(3, len(pixel))):  # RGB için 3, RGBA için 4
                    if data_index < len(binary_message):
                        # LSB'yi değiştir - Hata düzeltmesi: 0-255 aralığında tutmak için
                        pixel_value = img_array[i, j, color_channel]
                        # LSB'yi 0 yap
                        pixel_value = pixel_value & ~1
                        # Mesaj bitini ekle
                        pixel_value = pixel_value | int(binary_message[data_index])
                        # Değeri 0-255 aralığında tut
                        img_array[i, j, color_channel] = np.clip(pixel_value, 0, 255)

                        data_index += 1
                        modified = True
                    else:
                        break

                if data_index >= len(binary_message):
                    break
            if data_index >= len(binary_message):
                break

        if not modified:
            raise ValueError("Mesaj görüntüye yerleştirilemedi.")

        # Sonucu kaydet
        output_img = Image.fromarray(img_array)
        output_img.save(output_path)
        return True

    def extract_data(self, image_path, encryption=None, key=None):
        """Görüntüden veriyi çıkarır."""
        self.validate_image(image_path)

        # Görüntüyü aç
        img = Image.open(image_path)
        width, height = img.size
        img_array = np.array(img)

        # LSB'leri çıkar
        binary_message = ''

        for i in range(height):
            for j in range(width):
                pixel = img_array[i, j]

                # Her pikselin her renk kanalındaki LSB'yi al
                for color_channel in range(min(3, len(pixel))):  # RGB için 3, RGBA için 4
                    binary_message += str(img_array[i, j, color_channel] & 1)

                    # Yeterli miktarda veri toplandıysa...
                    if len(binary_message) % 8 == 0 and len(binary_message) >= self.header_size * 8:
                        # Metadata ve mesaj ayrımını ara
                        text_so_far = self.binary_to_text(binary_message)
                        if '|' in text_so_far:
                            metadata_json, message = text_so_far.split('|', 1)
                            try:
                                metadata = json.loads(metadata_json)
                                if len(message) >= metadata['length']:
                                    # Mesaj tam olarak çıkarıldı
                                    message = message[:metadata['length']]

                                    # Şifre çözme
                                    if metadata['encryption'] == 'aes' and encryption == 'aes':
                                        message = self._decrypt_aes(message, key)
                                    elif metadata['encryption'] == 'rsa' and encryption == 'rsa':
                                        message = self._decrypt_rsa(message, key)

                                    return {
                                        'message': message,
                                        'metadata': metadata
                                    }
                            except json.JSONDecodeError:
                                pass  # Geçersiz JSON, devam et

        raise ValueError("Görüntüde gizli mesaj bulunamadı veya hasar görmüş.")

    def _encrypt_aes(self, message, key):
        """AES-256 ile mesajı şifreler."""
        if not key:
            raise ValueError("AES şifrelemesi için anahtar gereklidir.")

        # Anahtar 32 byte (256 bit) olmalı
        if len(key) < 32:
            # Anahtarı genişlet
            key = key.ljust(32, '0')
        key = key[:32].encode()

        # Initialization Vector (IV) - Rastgele 16 byte
        iv = os.urandom(16)

        # Mesajı şifrele
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # IV ve şifreli veriyi birleştir
        result = base64.b64encode(iv + encrypted_data).decode()
        return result

    def _decrypt_aes(self, encrypted_message, key):
        """AES-256 ile şifrelenmiş mesajı çözer."""
        if not key:
            raise ValueError("AES şifre çözme için anahtar gereklidir.")

        # Anahtar 32 byte (256 bit) olmalı
        if len(key) < 32:
            key = key.ljust(32, '0')
        key = key[:32].encode()

        # Base64 decode
        encrypted_data = base64.b64decode(encrypted_message)

        # IV ilk 16 byte
        iv = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]

        # Şifreyi çöz
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Padding'i kaldır
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data.decode()

    def generate_rsa_keys(self, key_size=2048):
        """RSA anahtar çifti oluşturur."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Anahtarları PEM formatında kaydet
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        return {
            'private_key': private_pem.decode(),
            'public_key': public_pem.decode()
        }

    def _encrypt_rsa(self, message, public_key_pem):
        """RSA ile mesajı şifreler."""
        if not public_key_pem:
            raise ValueError("RSA şifrelemesi için açık anahtar gereklidir.")

        # PEM formatından public key'i yükle
        public_key = load_pem_public_key(public_key_pem.encode(), backend=default_backend())

        # Mesajı şifrele (RSA ile sadece küçük mesajlar şifrelenebilir)
        # Daha büyük mesajlar için hibrit şifreleme gerekebilir
        encrypted_data = public_key.encrypt(
            message.encode(),
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(encrypted_data).decode()

    def _decrypt_rsa(self, encrypted_message, private_key_pem):
        """RSA ile şifrelenmiş mesajı çözer."""
        if not private_key_pem:
            raise ValueError("RSA şifre çözme için özel anahtar gereklidir.")

        # PEM formatından private key'i yükle
        private_key = load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )

        # Şifreyi çöz
        encrypted_data = base64.b64decode(encrypted_message)
        decrypted_data = private_key.decrypt(
            encrypted_data,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted_data.decode()

    def add_watermark(self, image_path, watermark_text, output_path):
        """Görüntüye filigran ekler."""
        metadata = {
            'type': 'watermark',
            'text': watermark_text,
            'timestamp': datetime.now().isoformat()
        }

        return self.embed_data(image_path, json.dumps(metadata), output_path)

    def extract_watermark(self, image_path):
        """Görüntüden filigranı çıkarır."""
        result = self.extract_data(image_path)
        try:
            metadata = json.loads(result['message'])
            if metadata.get('type') == 'watermark':
                return metadata
        except:
            pass

        raise ValueError("Bu görüntüde filigran bulunamadı.")

# Modern GUI sınıfı - Yenilenmiş tasarım
class ModernGUI:
    def __init__(self, tool):
        self.tool = tool
        self.window = tk.Tk()
        self.window.title("StegoCrypt - Gelişmiş Steganografi Aracı")

        # Ekranın ortasında açılmasını sağla
        window_width = 900
        window_height = 650
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()

        position_x = (screen_width // 2) - (window_width // 2)
        position_y = (screen_height // 2) - (window_height // 2)

        self.window.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")
        self.window.minsize(800, 650)

        # Daha okunaklı ve açık renkli tema
        self.colors = {
            "bg_dark": "#f2f2f2",  # Çok hafif siyah
            "bg_main": "#ffffff",  # Beyaz
            "bg_light": "#e6e6e6",  # Hafif şeffaf siyah
            "accent": "#007bff",  # Canlı mavi
            "accent_hover": "#0056b3",  # Koyu mavi
            "text_light": "#000000",  # Koyu siyah (okunaklı)
            "text_dark": "#333333",  # Koyu gri
            "success": "#28a745",  # Yeşil
            "warning": "#ffc107",  # Sarı
            "error": "#dc3545",  # Kırmızı
            "border": "#cccccc"  # Açık gri
        }

        self.window.configure(bg=self.colors["bg_main"])

        # Font ayarları
        self.fonts = {
            "header": ("Poppins", 16, "bold"),
            "normal": ("Poppins", 12),
            "button": ("Poppins", 12, "bold"),
            "monospace": ("Poppins", 12)
        }

        self.input_image_path = None
        self.output_image_path = None
        self.rsa_public_key = None
        self.rsa_private_key = None

        # Temel ikonları yükle
        self.setup_icons()

        # Temayı ayarla
        self.setup_theme()

        # Arayüzü oluştur
        self._create_widgets()

    def setup_icons(self):
        """İkonları hazırlar"""
        # İkon dosya yolları
        icon_paths = {
            "lock": "icons/lock.png",
            "unlock": "icons/unlock.png",
            "key": "icons/key.png",
            "file": "icons/file.png",
            "info": "icons/info.png",
            "github": "icons/github.png"
        }

        # İkonları yükle
        self.icon_images = {}
        try:
            for icon_name, icon_path in icon_paths.items():
                # Tam dosya yolunu oluştur
                full_path = os.path.join(os.path.dirname(__file__), icon_path)
                if os.path.exists(full_path):
                    # İkonu yükle ve yeniden boyutlandır
                    image = Image.open(full_path)
                    image = image.resize((24, 24), Image.Resampling.LANCZOS)  # 24x24 piksel
                    self.icon_images[icon_name] = ImageTk.PhotoImage(image)
                else:
                    print(f"İkon dosyası bulunamadı: {full_path}")
                    self.icon_images[icon_name] = None

        except Exception as e:
            print(f"İkonlar yüklenemedi: {e}")
            # Boş ikonlar tanımla
            self.icon_images = {
                "lock": None,
                "unlock": None,
                "key": None,
                "file": None,
                "info": None,
                "github": None
            }

    def setup_theme(self):
        """Temayı ayarlar"""
        self.window.configure(bg=self.colors["bg_main"])

        # Stil tanımlamaları
        style = ttk.Style()
        style.theme_use('clam')  # Daha modern temayı kullan

        # Genel stil tanımlamaları
        style.configure('TFrame', background=self.colors["bg_main"])
        style.configure('TLabel', background=self.colors["bg_main"], foreground=self.colors["text_light"])
        style.configure('TButton', background=self.colors["accent"], foreground=self.colors["text_light"],
                        font=self.fonts["button"])
        style.map('TButton',
                 background=[('active', self.colors["accent_hover"]), ('pressed', self.colors["accent_hover"])],
                 foreground=[('active', self.colors["text_light"])])

        # Notebook ayarları
        style.configure('TNotebook', background=self.colors["bg_dark"], borderwidth=0)
        style.configure('TNotebook.Tab', background=self.colors["bg_light"], foreground=self.colors["text_dark"],
                        padding=[10, 2], font=self.fonts["normal"])
        style.map('TNotebook.Tab',
                 background=[('selected', self.colors["accent"])],
                 foreground=[('selected', self.colors["text_light"])])

        # LabelFrame ayarları
        style.configure('TLabelframe', background=self.colors["bg_light"], foreground=self.colors["text_light"])
        style.configure('TLabelframe.Label', background=self.colors["bg_light"], foreground=self.colors["accent"],
                        font=self.fonts["normal"])

        # Entry ayarları
        style.configure('TEntry', fieldbackground=self.colors["bg_dark"], foreground=self.colors["text_light"],
                       insertcolor=self.colors["text_light"])

        # Text widget için
        self.window.option_add("*Text.Background", self.colors["bg_dark"])
        self.window.option_add("*Text.Foreground", self.colors["text_light"])
        self.window.option_add("*Text.selectBackground", self.colors["accent"])
        self.window.option_add("*Text.insertBackground", self.colors["text_light"])

        # Radiobutton ayarları
        style.configure('TRadiobutton', background=self.colors["bg_light"], foreground=self.colors["text_light"])
        style.map('TRadiobutton',
                 background=[('active', self.colors["bg_light"])],
                 foreground=[('active', self.colors["text_light"])])

        # Combobox ayarları
        style.configure('TCombobox', fieldbackground=self.colors["bg_dark"], foreground=self.colors["text_dark"],
                      selectbackground=self.colors["accent"])

        # ScrollBar
        style.configure("Vertical.TScrollbar", gripcount=0,
                        background=self.colors["bg_light"], darkcolor=self.colors["bg_light"],
                        lightcolor=self.colors["bg_light"], troughcolor=self.colors["bg_dark"],
                        arrowcolor=self.colors["text_light"], bordercolor=self.colors["border"])

    def _create_widgets(self):
        # Logo ekle
        try:
            logo_path = os.path.join(os.path.dirname(__file__), "icons/logo.png")
            if os.path.exists(logo_path):
                # Logo yükle ve boyutlandır
                logo_image = Image.open(logo_path)
                # Logonun ortasını al (400x100 piksel)
                width, height = logo_image.size
                left = (width - 400) // 2
                top = (height - 100) // 2
                logo_image = logo_image.crop((left, top, left + 400, top + 100))
                self.logo_photo = ImageTk.PhotoImage(logo_image)

                # Logo için frame oluştur
                logo_frame = ttk.Frame(self.window)
                logo_frame.pack(pady=10)
                logo_label = ttk.Label(logo_frame, image=self.logo_photo)
                logo_label.pack()
        except Exception as e:
            print(f"Logo yüklenemedi: {e}")

        # Ana notebook
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Gizleme sayfası
        embed_frame = ttk.Frame(notebook)
        notebook.add(embed_frame, text="Veri Gizleme")
        self._create_embed_frame(embed_frame)

        # Çıkarma sayfası
        extract_frame = ttk.Frame(notebook)
        notebook.add(extract_frame, text="Veri Çıkarma")
        self._create_extract_frame(extract_frame)

        # Filigran sayfası
        watermark_frame = ttk.Frame(notebook)
        notebook.add(watermark_frame, text="Filigran")
        self._create_watermark_frame(watermark_frame)

        # Anahtar oluşturma sayfası
        keygen_frame = ttk.Frame(notebook)
        notebook.add(keygen_frame, text="RSA Anahtar Oluştur")
        self._create_keygen_frame(keygen_frame)

        # GitHub bağlantısı
        github_frame = ttk.Frame(self.window)
        github_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

        github_btn = ttk.Button(github_frame, text="github.com/captainmgc",
                               command=lambda: webbrowser.open("https://github.com/captainmgc"))
        if self.icon_images["github"]:
            github_btn.config(image=self.icon_images["github"], compound=tk.LEFT)
        github_btn.pack(side=tk.RIGHT, padx=10)

        # Durum çubuğu
        status_frame = ttk.Frame(self.window)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_var = tk.StringVar()
        status_bar = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W,
                              background=self.colors["bg_dark"], foreground=self.colors["text_light"],
                              padding=(5, 2))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var.set("Hazır")

    def _create_embed_frame(self, parent):
        # Üst kısım - görsel seçimi ve gizleme seçenekleri
        top_frame = ttk.Frame(parent)
        top_frame.pack(fill=tk.X, expand=False, padx=5, pady=5)

        # Sol panel - görsel seçimi
        left_panel = ttk.Frame(top_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Input görüntü seçimi
        input_frame = ttk.LabelFrame(left_panel, text="Giriş Görseli")
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        input_entry_frame = ttk.Frame(input_frame)
        input_entry_frame.pack(fill=tk.X, padx=5, pady=5)

        self.embed_input_path_var = tk.StringVar()
        ttk.Entry(input_entry_frame, textvariable=self.embed_input_path_var, width=40).pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)

        browse_btn = ttk.Button(input_entry_frame, text="Gözat", command=self._browse_embed_input)
        if self.icon_images["file"]:
            browse_btn.config(image=self.icon_images["file"], compound=tk.LEFT)
        browse_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # Output görüntü seçimi
        output_frame = ttk.LabelFrame(left_panel, text="Çıkış Görseli")
        output_frame.pack(fill=tk.X, padx=5, pady=5)

        output_entry_frame = ttk.Frame(output_frame)
        output_entry_frame.pack(fill=tk.X, padx=5, pady=5)

        self.embed_output_path_var = tk.StringVar()
        ttk.Entry(output_entry_frame, textvariable=self.embed_output_path_var, width=40).pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)

        browse_btn = ttk.Button(output_entry_frame, text="Gözat", command=self._browse_embed_output)
        if self.icon_images["file"]:
            browse_btn.config(image=self.icon_images["file"], compound=tk.LEFT)
        browse_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # Sağ panel - şifreleme seçenekleri
        right_panel = ttk.Frame(top_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Şifreleme ayarları
        encryption_frame = ttk.LabelFrame(right_panel, text="Şifreleme Seçenekleri")
        encryption_frame.pack(fill=tk.BOTH, padx=5, pady=5, expand=True)

        self.embed_encryption_var = tk.StringVar(value="none")

        # Şifreleme yok
        encryption_option = ttk.Frame(encryption_frame, padding=5)
        encryption_option.pack(fill=tk.X, padx=5, pady=2)

        none_radio = ttk.Radiobutton(encryption_option, text="Şifreleme Yok", variable=self.embed_encryption_var, value="none")
        if self.icon_images["unlock"]:
            none_radio.config(image=self.icon_images["unlock"], compound=tk.LEFT)
        none_radio.pack(anchor=tk.W)

        # AES şifreleme
        encryption_option = ttk.Frame(encryption_frame, padding=5)
        encryption_option.pack(fill=tk.X, padx=5, pady=2)

        aes_radio = ttk.Radiobutton(encryption_option, text="AES-256 Şifreleme", variable=self.embed_encryption_var, value="aes")
        if self.icon_images["lock"]:
            aes_radio.config(image=self.icon_images["lock"], compound=tk.LEFT)
        aes_radio.pack(anchor=tk.W)

        # AES anahtar girişi
        key_frame = ttk.Frame(encryption_frame, padding=5)
        key_frame.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(key_frame, text="AES Anahtarı:").pack(side=tk.LEFT, padx=2)
        self.embed_aes_key_var = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.embed_aes_key_var, width=20, show="*").pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)

        # RSA şifreleme
        encryption_option = ttk.Frame(encryption_frame, padding=5)
        encryption_option.pack(fill=tk.X, padx=5, pady=2)

        rsa_radio = ttk.Radiobutton(encryption_option, text="RSA Şifreleme", variable=self.embed_encryption_var, value="rsa")
        if self.icon_images["key"]:
            rsa_radio.config(image=self.icon_images["key"], compound=tk.LEFT)
        rsa_radio.pack(anchor=tk.W)

        # RSA anahtar seçimi
        rsa_key_frame = ttk.Frame(encryption_frame, padding=5)
        rsa_key_frame.pack(fill=tk.X, padx=5, pady=2)

        key_btn = ttk.Button(rsa_key_frame, text="RSA Açık Anahtar Seç", command=self._browse_public_key)
        key_btn.pack(side=tk.LEFT, padx=5)

        self.embed_public_key_label = ttk.Label(rsa_key_frame, text="Anahtar seçilmedi")
        self.embed_public_key_label.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)

        # Bilgi butonu
        info_btn = ttk.Button(encryption_frame, text="Bilgi", command=lambda: self._show_info("embed_encryption"))
        if self.icon_images["info"]:
            info_btn.config(image=self.icon_images["info"], compound=tk.LEFT)
        info_btn.pack(side=tk.BOTTOM, padx=5, pady=5, anchor=tk.SE)

        # Mesaj girişi (orta kısım)
        message_frame = ttk.LabelFrame(parent, text="Gizlenecek Mesaj")
        message_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Scrollbar ekle
        scroll_frame = ttk.Frame(message_frame)
        scroll_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(scroll_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.embed_message_text = tk.Text(scroll_frame, height=10, yscrollcommand=scrollbar.set)
        self.embed_message_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar.config(command=self.embed_message_text.yview)

        # Butonlar (alt kısım)
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, padx=10, pady=10)

        # Dosyadan yükleme butonu
        file_btn = ttk.Button(button_frame, text="Dosyadan Yükle", command=self._load_message_file)
        if self.icon_images["file"]:
            file_btn.config(image=self.icon_images["file"], compound=tk.LEFT)
        file_btn.pack(side=tk.LEFT, padx=5)

        # Bilgi butonu
        info_btn = ttk.Button(button_frame, text="Bilgi", command=lambda: self._show_info("embed"))
        if self.icon_images["info"]:
            info_btn.config(image=self.icon_images["info"], compound=tk.LEFT)
        info_btn.pack(side=tk.LEFT, padx=5)

        # Gizleme butonu
        embed_btn = ttk.Button(button_frame, text="Mesajı Gizle", command=self._embed_data)
        if self.icon_images["lock"]:
            embed_btn.config(image=self.icon_images["lock"], compound=tk.LEFT)
        embed_btn.pack(side=tk.RIGHT, padx=5)

    def _create_extract_frame(self, parent):
        # Üst kısım - görsel seçimi ve şifreleme seçenekleri
        top_frame = ttk.Frame(parent)
        top_frame.pack(fill=tk.X, expand=False, padx=5, pady=5)

        # Sol panel - görsel seçimi
        left_panel = ttk.Frame(top_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Input görüntü seçimi
        input_frame = ttk.LabelFrame(left_panel, text="Görsel Dosyası")
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        input_entry_frame = ttk.Frame(input_frame)
        input_entry_frame.pack(fill=tk.X, padx=5, pady=5)

        self.extract_input_path_var = tk.StringVar()
        ttk.Entry(input_entry_frame, textvariable=self.extract_input_path_var, width=40).pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)

        browse_btn = ttk.Button(input_entry_frame, text="Gözat", command=self._browse_extract_input)
        if self.icon_images["file"]:
            browse_btn.config(image=self.icon_images["file"], compound=tk.LEFT)
        browse_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # Sağ panel - şifreleme seçenekleri
        right_panel = ttk.Frame(top_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Şifreleme ayarları
        encryption_frame = ttk.LabelFrame(right_panel, text="Şifreleme Seçenekleri")
        encryption_frame.pack(fill=tk.BOTH, padx=5, pady=5, expand=True)

        self.extract_encryption_var = tk.StringVar(value="none")

        # Şifreleme yok
        encryption_option = ttk.Frame(encryption_frame, padding=5)
        encryption_option.pack(fill=tk.X, padx=5, pady=2)

        none_radio = ttk.Radiobutton(encryption_option, text="Şifreleme Yok", variable=self.extract_encryption_var, value="none")
        if self.icon_images["unlock"]:
            none_radio.config(image=self.icon_images["unlock"], compound=tk.LEFT)
        none_radio.pack(anchor=tk.W)

        # AES şifreleme
        encryption_option = ttk.Frame(encryption_frame, padding=5)
        encryption_option.pack(fill=tk.X, padx=5, pady=2)

        aes_radio = ttk.Radiobutton(encryption_option, text="AES-256 Şifreleme", variable=self.extract_encryption_var, value="aes")
        if self.icon_images["lock"]:
            aes_radio.config(image=self.icon_images["lock"], compound=tk.LEFT)
        aes_radio.pack(anchor=tk.W)

        # AES anahtar girişi
        key_frame = ttk.Frame(encryption_frame, padding=5)
        key_frame.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(key_frame, text="AES Anahtarı:").pack(side=tk.LEFT, padx=2)
        self.extract_aes_key_var = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.extract_aes_key_var, width=20, show="*").pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)

        # RSA şifreleme
        encryption_option = ttk.Frame(encryption_frame, padding=5)
        encryption_option.pack(fill=tk.X, padx=5, pady=2)

        rsa_radio = ttk.Radiobutton(encryption_option, text="RSA Şifreleme", variable=self.extract_encryption_var, value="rsa")
        if self.icon_images["key"]:
            rsa_radio.config(image=self.icon_images["key"], compound=tk.LEFT)
        rsa_radio.pack(anchor=tk.W)

        # RSA anahtar seçimi
        rsa_key_frame = ttk.Frame(encryption_frame, padding=5)
        rsa_key_frame.pack(fill=tk.X, padx=5, pady=2)

        key_btn = ttk.Button(rsa_key_frame, text="RSA Özel Anahtar Seç", command=self._browse_private_key)
        key_btn.pack(side=tk.LEFT, padx=5)

        self.extract_private_key_label = ttk.Label(rsa_key_frame, text="Anahtar seçilmedi")
        self.extract_private_key_label.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)

        # Bilgi butonu
        info_btn = ttk.Button(encryption_frame, text="Bilgi", command=lambda: self._show_info("extract_encryption"))
        if self.icon_images["info"]:
            info_btn.config(image=self.icon_images["info"], compound=tk.LEFT)
        info_btn.pack(side=tk.BOTTOM, padx=5, pady=5, anchor=tk.SE)

        # Çıkarılan mesaj (orta kısım)
        message_frame = ttk.LabelFrame(parent, text="Çıkarılan Mesaj")
        message_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Scrollbar ekle
        scroll_frame = ttk.Frame(message_frame)
        scroll_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(scroll_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.extract_message_text = tk.Text(scroll_frame, height=10, state=tk.DISABLED, yscrollcommand=scrollbar.set)
        self.extract_message_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar.config(command=self.extract_message_text.yview)

        # Metadata bilgileri
        metadata_frame = ttk.LabelFrame(parent, text="Metadata Bilgileri")
        metadata_frame.pack(fill=tk.X, padx=10, pady=5)

        # Scrollbar ekle
        meta_scroll_frame = ttk.Frame(metadata_frame)
        meta_scroll_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        meta_scrollbar = ttk.Scrollbar(meta_scroll_frame)
        meta_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.extract_metadata_text = tk.Text(meta_scroll_frame, height=4, state=tk.DISABLED, yscrollcommand=meta_scrollbar.set)
        self.extract_metadata_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        meta_scrollbar.config(command=self.extract_metadata_text.yview)

        # Butonlar (alt kısım)
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, padx=10, pady=10)

        # Mesajı kaydet butonu
        save_btn = ttk.Button(button_frame, text="Mesajı Dosyaya Kaydet", command=self._save_extracted_message)
        if self.icon_images["file"]:
            save_btn.config(image=self.icon_images["file"], compound=tk.LEFT)
        save_btn.pack(side=tk.LEFT, padx=5)

        # Bilgi butonu
        info_btn = ttk.Button(button_frame, text="Bilgi", command=lambda: self._show_info("extract"))
        if self.icon_images["info"]:
            info_btn.config(image=self.icon_images["info"], compound=tk.LEFT)
        info_btn.pack(side=tk.LEFT, padx=5)

        # Çıkarma butonu
        extract_btn = ttk.Button(button_frame, text="Mesajı Çıkar", command=self._extract_data)
        if self.icon_images["unlock"]:
            extract_btn.config(image=self.icon_images["unlock"], compound=tk.LEFT)
        extract_btn.pack(side=tk.RIGHT, padx=5)

    def _create_watermark_frame(self, parent):
        # Üst kısım - görsel seçimi
        top_frame = ttk.Frame(parent)
        top_frame.pack(fill=tk.X, expand=False, padx=5, pady=5)

        # Görsel seçimi
        input_frame = ttk.LabelFrame(top_frame, text="Giriş Görseli")
        input_frame.pack(fill=tk.X, padx=10, pady=5)

        input_entry_frame = ttk.Frame(input_frame)
        input_entry_frame.pack(fill=tk.X, padx=5, pady=5)

        self.watermark_input_path_var = tk.StringVar()
        ttk.Entry(input_entry_frame, textvariable=self.watermark_input_path_var, width=50).pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)

        browse_btn = ttk.Button(input_entry_frame, text="Gözat", command=self._browse_watermark_input)
        if self.icon_images["file"]:
            browse_btn.config(image=self.icon_images["file"], compound=tk.LEFT)
        browse_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # Output görüntü seçimi
        output_frame = ttk.LabelFrame(top_frame, text="Çıkış Görseli")
        output_frame.pack(fill=tk.X, padx=10, pady=5)

        output_entry_frame = ttk.Frame(output_frame)
        output_entry_frame.pack(fill=tk.X, padx=5, pady=5)

        self.watermark_output_path_var = tk.StringVar()
        ttk.Entry(output_entry_frame, textvariable=self.watermark_output_path_var, width=50).pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)

        browse_btn = ttk.Button(output_entry_frame, text="Gözat", command=self._browse_watermark_output)
        if self.icon_images["file"]:
            browse_btn.config(image=self.icon_images["file"], compound=tk.LEFT)
        browse_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # İşlemler bölümü - sol ve sağ panel
        operations_frame = ttk.Frame(parent)
        operations_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Sol panel - filigran ekleme
        left_panel = ttk.LabelFrame(operations_frame, text="Filigran Ekleme")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Filigran metni
        watermark_text_frame = ttk.Frame(left_panel)
        watermark_text_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(watermark_text_frame, text="Filigran Metni:").pack(anchor=tk.W, padx=5, pady=2)

        self.watermark_text_var = tk.StringVar()
        ttk.Entry(watermark_text_frame, textvariable=self.watermark_text_var).pack(fill=tk.X, padx=5, pady=5)

        # Filigran ekleme butonu
        add_btn = ttk.Button(watermark_text_frame, text="Filigran Ekle", command=self._add_watermark)
        if self.icon_images["lock"]:
            add_btn.config(image=self.icon_images["lock"], compound=tk.LEFT)
        add_btn.pack(padx=5, pady=10)

        # Bilgi butonu
        info_btn = ttk.Button(left_panel, text="Bilgi", command=lambda: self._show_info("watermark_add"))
        if self.icon_images["info"]:
            info_btn.config(image=self.icon_images["info"], compound=tk.LEFT)
        info_btn.pack(side=tk.BOTTOM, padx=5, pady=5, anchor=tk.SE)

        # Sağ panel - filigran çıkarma
        right_panel = ttk.LabelFrame(operations_frame, text="Filigran Çıkarma")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Filigran çıkarma butonu
        extract_btn = ttk.Button(right_panel, text="Filigranı Çıkar", command=self._extract_watermark)
        if self.icon_images["unlock"]:
            extract_btn.config(image=self.icon_images["unlock"], compound=tk.LEFT)
        extract_btn.pack(padx=5, pady=10)

        # Çıkarılan filigran bilgileri
        scroll_frame = ttk.Frame(right_panel)
        scroll_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(scroll_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.watermark_info_text = tk.Text(scroll_frame, height=6, state=tk.DISABLED, yscrollcommand=scrollbar.set)
        self.watermark_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar.config(command=self.watermark_info_text.yview)

        # Bilgi butonu
        info_btn = ttk.Button(right_panel, text="Bilgi", command=lambda: self._show_info("watermark_extract"))
        if self.icon_images["info"]:
            info_btn.config(image=self.icon_images["info"], compound=tk.LEFT)
        info_btn.pack(side=tk.BOTTOM, padx=5, pady=5, anchor=tk.SE)

    def _create_keygen_frame(self, parent):
        # Hızlı seçenekler
        options_frame = ttk.LabelFrame(parent, text="Anahtar Oluşturma Seçenekleri")
        options_frame.pack(fill=tk.X, padx=10, pady=10)

        inner_frame = ttk.Frame(options_frame)
        inner_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(inner_frame, text="Anahtar Boyutu:").pack(side=tk.LEFT, padx=5)

        self.key_size_var = tk.StringVar(value="2048")
        key_size_combo = ttk.Combobox(inner_frame, textvariable=self.key_size_var, width=10,
                                     values=("1024", "2048", "4096"))
        key_size_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(inner_frame, text="Dosya Öneki:").pack(side=tk.LEFT, padx=15)

        self.key_prefix_var = tk.StringVar(value="stegocrypt_key")
        ttk.Entry(inner_frame, textvariable=self.key_prefix_var, width=20).pack(side=tk.LEFT, padx=5)

        # Bilgi butonu
        info_btn = ttk.Button(inner_frame, text="Bilgi", command=lambda: self._show_info("keygen"))
        if self.icon_images["info"]:
            info_btn.config(image=self.icon_images["info"], compound=tk.LEFT)
        info_btn.pack(side=tk.RIGHT, padx=5)

        # Anahtar oluşturma butonu
        key_btn = ttk.Button(options_frame, text="RSA Anahtar Çifti Oluştur", command=self._generate_rsa_keys)
        if self.icon_images["key"]:
            key_btn.config(image=self.icon_images["key"], compound=tk.LEFT)
        key_btn.pack(pady=10)

        # Anahtar bilgileri
        key_info_frame = ttk.LabelFrame(parent, text="Oluşturulan Anahtarlar")
        key_info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Scrollbar ekle
        scroll_frame = ttk.Frame(key_info_frame)
        scroll_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(scroll_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.key_info_text = tk.Text(scroll_frame, height=10, state=tk.DISABLED, yscrollcommand=scrollbar.set)
        self.key_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar.config(command=self.key_info_text.yview)

    def _show_info(self, info_type):
        """Bilgi mesajlarını gösterir"""
        info_messages = {
            "embed": """
Veri Gizleme Hakkında Bilgi:

Bu sekme, herhangi bir metni bir görüntü dosyasına gizlemenizi sağlar. Gizleme işlemi, görüntüdeki piksellerin en düşük anlamlı bitlerini (LSB) değiştirerek gerçekleştirilir.

Kullanım:
1. Giriş görseli seçin (PNG, BMP, JPG, JPEG, TIFF, GIF, WEBP formatları desteklenir)
2. Çıkış görseli için bir konum belirleyin
3. Gizlemek istediğiniz metni yazın veya bir dosyadan yükleyin
4. İsteğe bağlı olarak şifreleme yöntemi seçin
5. "Mesajı Gizle" butonuna tıklayın

Not: PNG ve BMP formatları kayıpsız sıkıştırma kullandığından en iyi sonuçları verir.
            """,

            "embed_encryption": """
Şifreleme Seçenekleri Hakkında Bilgi:

1. Şifreleme Yok: Mesaj olduğu gibi gizlenir, herhangi biri görseli analiz ederek mesajı çıkarabilir.

2. AES-256 Şifreleme: Mesaj, girdiğiniz anahtar ile AES-256 algoritması kullanılarak şifrelenir. Mesajı çıkarmak için aynı anahtarı kullanmanız gerekir.

3. RSA Şifreleme: Mesaj, seçtiğiniz RSA açık anahtar ile şifrelenir. Mesajı çıkarmak için eşleşen özel anahtarı kullanmanız gerekir.

Not: RSA, AES'e göre daha güvenli ancak daha büyük mesajlar için uygun değildir.
            """,

            "extract": """
Veri Çıkarma Hakkında Bilgi:

Bu sekme, daha önce StegoCrypt ile gizlenmiş bir mesajı bir görüntü dosyasından çıkarmanızı sağlar.

Kullanım:
1. Gizli mesaj içeren görüntü dosyasını seçin
2. Mesaj şifrelenmişse, doğru şifreleme yöntemini ve anahtarı seçin
3. "Mesajı Çıkar" butonuna tıklayın
4. Çıkarılan mesajı görüntüleyin veya dosyaya kaydedin

Not: Metadata bölümünde, mesajın ne zaman gizlendiği ve hangi şifreleme yöntemi kullanıldığı gibi bilgiler görüntülenir.
            """,

            "extract_encryption": """
Şifre Çözme Seçenekleri Hakkında Bilgi:

1. Şifreleme Yok: Mesaj şifrelenmemişse bu seçeneği kullanın.

2. AES-256 Şifreleme: Mesaj AES-256 ile şifrelenmişse, şifreyi çözmek için kullanılan anahtarı girin.

3. RSA Şifreleme: Mesaj RSA ile şifrelenmişse, şifreyi çözmek için özel anahtarı seçin.

Not: Yanlış şifreleme yöntemi veya anahtar kullanırsanız, mesaj doğru şekilde çözülemez.
            """,

            "watermark_add": """
Filigran Ekleme Hakkında Bilgi:

Filigran, bir görüntüye telif hakkı bilgisi veya sahiplik bilgisi eklemek için kullanılır. Filigran, görüntüyü görsel olarak değiştirmeden gizlenir.

Kullanım:
1. Giriş görseli seçin
2. Çıkış görseli için bir konum belirleyin
3. Filigran metnini girin (örn. "© 2025 CaptainMGC")
4. "Filigran Ekle" butonuna tıklayın

Not: Filigran, steganografi kullanılarak gizlenir ve görüntüyü görsel olarak etkilemez.
            """,

            "watermark_extract": """
Filigran Çıkarma Hakkında Bilgi:

Bu özellik, daha önce StegoCrypt ile eklenmiş bir filigranı bir görüntüden çıkarmanızı sağlar.

Kullanım:
1. Filigran içeren görüntü dosyasını seçin
2. "Filigranı Çıkar" butonuna tıklayın
3. Çıkarılan filigran bilgilerini görüntüleyin

Not: Filigran bilgileri, filigran metnini ve ne zaman eklendiğini içerir.
            """,

            "keygen": """
RSA Anahtar Oluşturma Hakkında Bilgi:

RSA, asimetrik bir şifreleme algoritmasıdır ve bir açık anahtar ve bir özel anahtar çifti kullanır. Açık anahtar mesajları şifrelemek için, özel anahtar ise şifrelenmiş mesajları çözmek için kullanılır.

Kullanım:
1. Anahtar boyutu seçin (bit cinsinden, daha büyük = daha güvenli ama daha yavaş)
2. Anahtar dosyaları için bir önek girin
3. "RSA Anahtar Çifti Oluştur" butonuna tıklayın
4. Oluşturulan anahtarları kullanın

ÖNEMLİ: Özel anahtarınızı güvenli bir yerde saklayın! Özel anahtarınız kaybolursa, şifrelenmiş mesajlarınızı çözemezsiniz.
            """
        }

        if info_type in info_messages:
            messagebox.showinfo("Bilgi", info_messages[info_type])
        else:
            messagebox.showinfo("Bilgi", "Bu özellik hakkında bilgi bulunmamaktadır.")

    def _browse_embed_input(self):
        file_types = [("Tüm Desteklenen Formatlar",
                     "*.png;*.bmp;*.jpg;*.jpeg;*.tiff;*.gif;*.webp")]
        for ext in self.tool.supported_formats:
            ext_clean = ext.replace(".", "")
            file_types.append((f"{ext_clean.upper()} Dosyaları", f"*.{ext_clean}"))
        file_types.append(("Tüm Dosyalar", "*.*"))

        file_path = filedialog.askopenfilename(
            title="Giriş Görselini Seç",
            filetypes=file_types
        )
        if file_path:
            self.embed_input_path_var.set(file_path)
            # Aynı isimde çıkış dosyası öner
            base, ext = os.path.splitext(file_path)
            self.embed_output_path_var.set(f"{base}_stego{ext}")

    def _browse_embed_output(self):
        file_types = []
        for ext in self.tool.supported_formats:
            ext_clean = ext.replace(".", "")
            file_types.append((f"{ext_clean.upper()} Dosyası", f"*.{ext_clean}"))

        file_path = filedialog.asksaveasfilename(
            title="Çıkış Görselini Seç",
            filetypes=file_types
        )
        if file_path:
            self.embed_output_path_var.set(file_path)

    def _browse_extract_input(self):
        file_types = [("Tüm Desteklenen Formatlar",
                     "*.png;*.bmp;*.jpg;*.jpeg;*.tiff;*.gif;*.webp")]
        for ext in self.tool.supported_formats:
            ext_clean = ext.replace(".", "")
            file_types.append((f"{ext_clean.upper()} Dosyaları", f"*.{ext_clean}"))
        file_types.append(("Tüm Dosyalar", "*.*"))

        file_path = filedialog.askopenfilename(
            title="Görsel Dosyasını Seç",
            filetypes=file_types
        )
        if file_path:
            self.extract_input_path_var.set(file_path)

    def _browse_watermark_input(self):
        file_types = [("Tüm Desteklenen Formatlar",
                     "*.png;*.bmp;*.jpg;*.jpeg;*.tiff;*.gif;*.webp")]
        for ext in self.tool.supported_formats:
            ext_clean = ext.replace(".", "")
            file_types.append((f"{ext_clean.upper()} Dosyaları", f"*.{ext_clean}"))
        file_types.append(("Tüm Dosyalar", "*.*"))

        file_path = filedialog.askopenfilename(
            title="Giriş Görselini Seç",
            filetypes=file_types
        )
        if file_path:
            self.watermark_input_path_var.set(file_path)
            # Aynı isimde çıkış dosyası öner
            base, ext = os.path.splitext(file_path)
            self.watermark_output_path_var.set(f"{base}_watermarked{ext}")

    def _browse_watermark_output(self):
        file_types = []
        for ext in self.tool.supported_formats:
            ext_clean = ext.replace(".", "")
            file_types.append((f"{ext_clean.upper()} Dosyası", f"*.{ext_clean}"))

        file_path = filedialog.asksaveasfilename(
            title="Çıkış Görselini Seç",
            filetypes=file_types
        )
        if file_path:
            self.watermark_output_path_var.set(file_path)

    def _browse_public_key(self):
        file_path = filedialog.askopenfilename(
            title="RSA Açık Anahtarı Seç",
            filetypes=[("PEM Dosyaları", "*.pem"), ("Tüm Dosyalar", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    self.rsa_public_key = f.read()
                self.embed_public_key_label.config(text=f"...{os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Hata", f"Anahtar dosyası okunamadı: {e}")

    def _browse_private_key(self):
        file_path = filedialog.askopenfilename(
            title="RSA Özel Anahtarı Seç",
            filetypes=[("PEM Dosyaları", "*.pem"), ("Tüm Dosyalar", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    self.rsa_private_key = f.read()
                self.extract_private_key_label.config(text=f"...{os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Hata", f"Anahtar dosyası okunamadı: {e}")

    def _load_message_file(self):
        file_path = filedialog.askopenfilename(
            title="Mesaj Dosyasını Seç",
            filetypes=[("Metin Dosyaları", "*.txt"), ("Tüm Dosyalar", "*.*")]
        )
        if file_path:
            try:
                # Büyük dosyalar için chunked okuma
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.embed_message_text.delete(1.0, tk.END)
                    while chunk := f.read(8192):  # 8KB chunks
                        self.embed_message_text.insert(tk.END, chunk)
            except Exception as e:
                messagebox.showerror("Hata", f"Dosya okunamadı: {e}")

    def _save_extracted_message(self):
        file_path = filedialog.asksaveasfilename(
            title="Mesajı Kaydet",
            filetypes=[("Metin Dosyaları", "*.txt"), ("Tüm Dosyalar", "*.*")]
        )
        if file_path:
            self._save_file_content(file_path, self.extract_message_text.get(1.0, tk.END))
            self.status_var.set(f"Mesaj '{file_path}' dosyasına kaydedildi.")

    def _save_file_content(self, file_path, content):
        """Dosya kaydetme işlemleri için yardımcı fonksiyon"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            messagebox.showerror("Hata", f"Dosya kaydedilemedi: {e}")
            return False

    def _handle_operation(self, operation_name, operation_func, *args):
        """Genel hata yönetimi için yardımcı fonksiyon"""
        try:
            self.status_var.set(f"{operation_name} işlemi yapılıyor...")
            self.window.update()

            result = operation_func(*args)

            self.status_var.set(f"{operation_name} işlemi başarılı.")
            return result

        except Exception as e:
            self.status_var.set(f"Hata: {e}")
            messagebox.showerror("Hata", str(e))
            return None

    def _embed_data(self):
        self._handle_operation("Mesaj gizleme", self._embed_data_operation)

    def _embed_data_operation(self):
        input_path = self.embed_input_path_var.get()
        output_path = self.embed_output_path_var.get()
        message = self.embed_message_text.get(1.0, tk.END).rstrip()
        encryption = self.embed_encryption_var.get()

        if not input_path or not output_path:
            raise ValueError("Giriş ve çıkış görselleri seçilmelidir.")

        if not message:
            raise ValueError("Gizlenecek mesaj boş olamaz.")

        encryption_key = None
        if encryption == "aes":
            encryption_key = self.embed_aes_key_var.get()
            if not encryption_key:
                raise ValueError("AES şifrelemesi için anahtar gereklidir.")
        elif encryption == "rsa":
            encryption_key = self.rsa_public_key
            if not encryption_key:
                raise ValueError("RSA şifrelemesi için açık anahtar gereklidir.")

        self.tool.embed_data(input_path, message, output_path, encryption, encryption_key)

        messagebox.showinfo("Başarılı", "Mesaj başarıyla gizlendi!")

    def _extract_data(self):
        self._handle_operation("Mesaj çıkarma", self._extract_data_operation)

    def _extract_data_operation(self):
        input_path = self.extract_input_path_var.get()
        encryption = self.extract_encryption_var.get()

        if not input_path:
            raise ValueError("Görsel dosyası seçilmelidir.")

        encryption_key = None
        if encryption == "aes":
            encryption_key = self.extract_aes_key_var.get()
            if not encryption_key:
                raise ValueError("AES şifre çözme için anahtar gereklidir.")
        elif encryption == "rsa":
            encryption_key = self.rsa_private_key
            if not encryption_key:
                raise ValueError("RSA şifre çözme için özel anahtar gereklidir.")

        result = self.tool.extract_data(input_path, encryption, encryption_key)

        # Mesajı göster
        self._update_text_widget(self.extract_message_text, result['message'])

        # Metadata bilgilerini göster
        metadata_text = ""
        for key, value in result['metadata'].items():
            metadata_text += f"{key}: {value}\n"

        self._update_text_widget(self.extract_metadata_text, metadata_text)

    def _add_watermark(self):
        self._handle_operation("Filigran ekleme", self._add_watermark_operation)

    def _add_watermark_operation(self):
        input_path = self.watermark_input_path_var.get()
        output_path = self.watermark_output_path_var.get()
        watermark_text = self.watermark_text_var.get()

        if not input_path or not output_path:
            raise ValueError("Giriş ve çıkış görselleri seçilmelidir.")

        if not watermark_text:
            raise ValueError("Filigran metni boş olamaz.")

        self.tool.add_watermark(input_path, watermark_text, output_path)

        messagebox.showinfo("Başarılı", "Filigran başarıyla eklendi!")

    def _extract_watermark(self):
        self._handle_operation("Filigran çıkarma", self._extract_watermark_operation)

    def _extract_watermark_operation(self):
        input_path = self.watermark_input_path_var.get()

        if not input_path:
            raise ValueError("Görsel dosyası seçilmelidir.")

        watermark = self.tool.extract_watermark(input_path)

        # watermark_text değişkeni tanımlanmamış, düzeltilmeli
        watermark_info = f"""
Filigran Bilgileri:
Metin: {watermark['text']}
Tarih: {watermark['timestamp']}
Tür: {watermark['type']}
"""
        self.watermark_info_text.config(state=tk.NORMAL)
        self.watermark_info_text.delete(1.0, tk.END)
        self.watermark_info_text.insert(tk.END, watermark_info)
        self.watermark_info_text.config(state=tk.DISABLED)

    def _generate_rsa_keys(self):
        self._handle_operation("RSA anahtar oluşturma", self._generate_rsa_keys_operation)

    def _generate_rsa_keys_operation(self):
        key_size = int(self.key_size_var.get())
        key_prefix = self.key_prefix_var.get()

        if not key_prefix:
            key_prefix = "stegocrypt_key"

        key_pair = self.tool.generate_rsa_keys(key_size)

        private_key_file = f"{key_prefix}_private.pem"
        public_key_file = f"{key_prefix}_public.pem"

        with open(private_key_file, 'w') as f:
            f.write(key_pair['private_key'])

        with open(public_key_file, 'w') as f:
            f.write(key_pair['public_key'])

        info_text = f"""
RSA Anahtar Çifti Oluşturuldu:
- Anahtar Boyutu: {key_size} bit
- Özel Anahtar: {private_key_file}
- Açık Anahtar: {public_key_file}

Anahtarlar başarıyla kaydedildi.
"""
        self._update_text_widget(self.key_info_text, info_text)

        messagebox.showinfo("Başarılı", "RSA anahtar çifti başarıyla oluşturuldu!")

    def _update_text_widget(self, widget, text):
        """Text widget'ları güncellemek için yardımcı fonksiyon"""
        widget.config(state=tk.NORMAL)
        widget.delete(1.0, tk.END)
        widget.insert(tk.END, text)
        widget.config(state=tk.DISABLED)

    def run(self):
        self.window.mainloop()

def main():
    tool = SteganographyTool()
    gui = ModernGUI(tool)
    gui.run()

if __name__ == "__main__":
    main()
