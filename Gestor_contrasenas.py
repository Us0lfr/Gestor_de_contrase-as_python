# Proyecto final

import tkinter as tk # cambiar más adeleante a custom
from tkinter import ttk, messagebox, simpledialog

# --- Aplicación --- #

class Aplicacion(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Gestor de Contraseñas")
        self.geometry("760x440")
        self.minsize(720,400)

        # -- Variables de estado para la Interfaz de Usuario -- #
        self.var_lenght = tk.IntVar(value=12)
        self.var_upper = tk.BooleanVar(value=True)
        self.var_digitos = tk.BooleanVar(value=True)
        self.var_symbols = tk.BooleanVar(value=True)
        self.var_show = tk.BooleanVar(value=False)
        self.var_password = tk.StringVar(value="")
        self.var_sitio_web = tk.StringVar(value="")
        self.var_usuario = tk.StringVar(value="")

        def construir_interfaz_usuario(self):

            " Creara los widgets, los agrupa, define los botonoes"
            pad = {"padx":12, "pady": 8}
            izquierda = ttk.Frame(self) # frame izquierdo
            izquierda.pack(side="left", fill="both", expand=True, **pad)
            derecha = ttk.Frame(self, width=280) # frame derecho
            derecha.pack(side="right", fill="y", padx=(0,12), pady=12)



# --- Programa principal --- #
if __name__ == '__main__':
    Aplicacion().mainloop()


