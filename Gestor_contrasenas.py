# Proyecto final
import customtkinter as ctk
import tkinter as tk # cambiar más adeleante a custom
from tkinter import ttk, messagebox, simpledialog

# Configuración inicial de CustomTkinter (Opcional pero recomendado)
ctk.set_appearance_mode("System")  # "System", "Dark", "Light"
ctk.set_default_color_theme("blue")  # "blue", "green", "dark-blue"

# --- Aplicación --- #

class Aplicacion(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("Gestor de Contraseñas")
        self.geometry("760x440")
        self.minsize(720,400)

        # --- Variables de estado para la Interfaz de Usuario --- #
        self.var_largo = ctk.IntVar(value=12)
        self.var_upper = ctk.BooleanVar(value=True)
        self.var_digitos = ctk.BooleanVar(value=True)
        self.var_symbols = ctk.BooleanVar(value=True)
        self.var_show = ctk.BooleanVar(value=False)
        self.var_password = ctk.StringVar(value="")
        self.var_sitio_web = ctk.StringVar(value="")
        self.var_usuario = ctk.StringVar(value="")

        # --- llamamos al método para crear la interfaz --- #
        self.construir_interfaz_usuario()

    def construir_interfaz_usuario(self):

        " Creara los widgets, los agrupa y define los botonoes"
        pad = {"padx":12, "pady": 8}
        izquierda = ctk.CTkFrame(self) # frame izquierdo
        izquierda.pack(side="left", fill="both", expand=True, **pad)
        derecha = ctk.CTkFrame(self, width=280) # frame derecho
        derecha.pack(side="right", fill="y", padx=(0,12), pady=12)

    # Opciones (LabelFrame se reemplaza por CTkFrame con título o CTkGroupBox)
        fo = ctk.CTkFrame(izquierda)
        fo.pack(fill="x", padx=5, pady=5)

        # Nota: CustomTkinter no trae un LabelFrame idéntico nativo por defecto,
        # pero podemos estructurarlo limpiamente o usar un Frame con título.
        lbl_titulo_opciones = ctk.CTkLabel(
            fo, text="Opciones", font=ctk.CTkFont(weight="bold")
        )
        lbl_titulo_opciones.pack(anchor="w", padx=10, pady=(8, 4))

        # Fila 1: Longitud y Slider
        fila1 = ctk.CTkFrame(fo, fg_color="transparent")  # Fondo transparente
        fila1.pack(fill="x", padx=8, pady=6)
        ctk.CTkLabel(fila1, text="Longitud:").pack(side="left")

        # Slider de CustomTkinter (ya incluye la opción 'variable')
        self.scale = ctk.CTkSlider(
            fila1, from_=6, to=64, number_of_steps=58, variable=self.var_largo
        )
        self.scale.pack(side="left", fill="x", expand=True, padx=8)

        # Etiqueta que muestra el valor numérico actual
        ctk.CTkLabel(fila1, textvariable=self.var_largo, width=3).pack(side="left")

        # Fila 2: Checkboxes
        fila2 = ctk.CTkFrame(fo, fg_color="transparent")
        fila2.pack(fill="x", padx=8, pady=(2, 10))

        for txt, var in [
            ("Mayúsculas", self.var_upper),
            ("Números", self.var_digitos),
            ("Símbolos", self.var_symbols),
        ]:
            ctk.CTkCheckBox(fila2, text=txt, variable=var).pack(
            side="left", padx=(0, 12)
        )

# --- Programa principal --- #
if __name__ == '__main__':
    Aplicacion().mainloop()


