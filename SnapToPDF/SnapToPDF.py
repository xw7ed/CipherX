import subprocess
import sys

# دالة لتثبيت المكتبات تلقائيًا إذا كانت ناقصة
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# محاولة استيراد كل مكتبة وتثبيتها إذا ما كانت موجودة
try:
    from PIL import Image, ImageTk
except ImportError:
    install("pillow")
    from PIL import Image, ImageTk

try:
    from reportlab.pdfgen import canvas
except ImportError:
    install("reportlab")
    from reportlab.pdfgen import canvas

try:
    import arabic_reshaper
except ImportError:
    install("arabic_reshaper")
    import arabic_reshaper

try:
    from bidi.algorithm import get_display
except ImportError:
    install("python-bidi")
    from bidi.algorithm import get_display



import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
import arabic_reshaper
from bidi.algorithm import get_display
import os

class ImageToPDFApp:
    def __init__(self, root):
        self.root = root
        self.root.title("تحويل الصور إلى PDF - xw7ed")
        self.root.geometry("500x400")
        self.root.configure(bg="#f0f0f0")

        # لوقو باسمك
        logo_label = tk.Label(root, text="xw7ed Tools", font=("Helvetica", 20, "bold"), bg="#f0f0f0", fg="#3b5998")
        logo_label.pack(pady=10)

        self.image_paths = []

        select_btn = tk.Button(root, text="اختر الصور", command=self.select_images, width=30, bg="#4CAF50", fg="white")
        select_btn.pack(pady=10)

        save_btn = tk.Button(root, text="تحويل إلى PDF وحفظ", command=self.save_pdf, width=30, bg="#2196F3", fg="white")
        save_btn.pack(pady=10)

    def select_images(self):
        filetypes = [("Image files", "*.jpg *.jpeg *.png *.bmp *.gif")]
        paths = filedialog.askopenfilenames(title="اختر الصور", filetypes=filetypes)
        if paths:
            self.image_paths = list(paths)
            messagebox.showinfo("تم التحميل", f"تم اختيار {len(self.image_paths)} صورة.")

    def save_pdf(self):
        if not self.image_paths:
            messagebox.showwarning("تحذير", "لم يتم اختيار صور بعد!")
            return

        pdf_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], title="حفظ PDF")
        if not pdf_path:
            return

        try:
            c = canvas.Canvas(pdf_path, pagesize=A4)
            width, height = A4
            
            for img_path in self.image_paths:
                img = Image.open(img_path)
                img.thumbnail((width, height))
                img_reader = ImageReader(img)
                img_width, img_height = img.size

                x = (width - img_width) / 2
                y = (height - img_height) / 2
                c.drawImage(img_reader, x, y)
                c.showPage()

            # نص عربي في النهاية (مثلاً توقيعك)
            text = "تم التحويل بواسطة xw7ed"
            reshaped_text = arabic_reshaper.reshape(text)
            bidi_text = get_display(reshaped_text)
            c.setFont("Helvetica", 14)
            c.drawRightString(width - 40, 40, bidi_text)

            c.save()
            messagebox.showinfo("نجاح", f"تم حفظ الملف بنجاح في:\n{pdf_path}")

        except Exception as e:
            messagebox.showerror("خطأ", f"حدث خطأ أثناء التحويل:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ImageToPDFApp(root)
    root.mainloop()
