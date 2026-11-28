# -*- coding: utf-8 -*-
#Dependencias: pip install customtkinter CTkMessagebox cryptography pillow

import base64, json, math, os, re, secrets, string, time, unicodedata, uuid  # módulos estándar: base64 (bytes↔texto), json (guardar datos), math (log2, ceil), os (urandom, archivos), re (expresiones regulares), secrets (aleatorios seguros), string (letras/dígitos), time (reloj), unicodedata (normalizar texto), uuid (IDs únicos)
from datetime import datetime  # clase para manejar fecha y hora
from pathlib import Path  # manejo moderno de rutas de archivos
import customtkinter as ctk  # librería de interfaz gráfica; se abrevia como ctk
from CTkMessagebox import CTkMessagebox  # ventanas emergentes de mensaje
from cryptography.fernet import Fernet, InvalidToken  # Fernet: cifrado simétrico listo para usar; InvalidToken es el error que lanza si la llave es incorrecta o el dato fue modificado
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # función que convierte la contraseña maestra en una llave (Fernet no lo hace por sí solo)

# -- Constantes con Rutas y parámetros de cifrado -- #
CARPETA_APP = Path(__file__).resolve().parent  # carpeta donde está este script (__file__ = ruta del script, resolve() la hace absoluta, parent = su carpeta)
CARPETA_BOVEDAS = CARPETA_APP / "boveda"  # subcarpeta "boveda" (el operador / une rutas en Path)
RUTA_BOVEDA = CARPETA_BOVEDAS / "gestor.vault"  # archivo de la bóveda; es la única bóveda de la aplicación
LOGO_IPN = CARPETA_APP / "IPN Logo.png"  # ruta de la imagen del logo del IPN
LOGO_MISTI = CARPETA_APP / "MISTI Logo.png"  # ruta de la imagen del logo de MISTI
IMAGEN_LOGIN = CARPETA_APP / "login_image.png" # ruta para cargar la imagen del login en el frame izquierdo

LARGO_SAL = 16  # bytes de la sal aleatoria que se mezcla con la contraseña maestra
MASTER_MIN_LARGO, MASTER_MIN_BITS = 12, 40  # mínimos para la contraseña maestra: 12 caracteres y 40 bits de entropía
PASSWORD_MIN_LARGO = 8  # largo mínimo de una contraseña que se guarda en la bóveda
LIMITE_HISTORIAL = 10  # máximo de versiones anteriores que se conservan por credencial
MAX_INTENTOS = 3  # intentos fallidos permitidos antes de bloquear el acceso
SEGUNDOS_BLOQUEO = 30  # duración del bloqueo tras agotar los intentos

REGEX_CORREO = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")  # patrón de correo: texto sin espacios ni @, luego @, dominio, punto y terminación; compile lo deja listo para reutilizar

# -- Colores: cada tupla es (tema claro, tema oscuro) -- #
GUINDA = "#741743"  # color institucional principal (código hexadecimal RGB)
GUINDA_HOVER = "#5C1034"  # guinda más oscuro, para cuando el mouse pasa sobre un botón
GUINDA_OSCURO = "#8B2455"  # guinda usado en elementos seleccionados del tema oscuro
NEUTRO = ("#626262", "#B5B5B5")  # gris para textos secundarios: (claro, oscuro)
PANEL = ("#F1F1F3", "#242427")  # fondo de los paneles según el tema
PANEL_ALT = ("#FFFFFF", "#2D2D31")  # fondo alterno (por ejemplo, la lista de credenciales)
BORDE = ("#D4D4D8", "#44444A")  # color de los bordes según el tema
TEXTO = ("#242424", "#F2F2F2")  # color del texto según el tema
ERROR = "#C0392B"  # rojo para errores
ADVERTENCIA = "#C47A19"  # naranja para advertencias
EXITO = "#27834A"  # verde para éxito
SUPREMO = "#2473DA"  # azul para el nivel más alto de fuerza

# Estilos reutilizables de botones (se aplican con **, igual que "pad" en el código simple)
BOTON_GUINDA = {"fg_color": GUINDA, "hover_color": GUINDA_HOVER}  # diccionario con color de fondo y de hover; ** lo desempaca como argumentos con nombre
BOTON_GRIS = {"fg_color": ("gray75", "gray35"), "text_color": ("#202020", "#FFFFFF"), "hover_color": ("gray65", "gray45")}  # estilo de botón gris con colores para ambos temas

ctk.set_appearance_mode("Light")  # el login siempre es oscuro
ctk.set_default_color_theme("blue")  # tema de color base de los widgets
ctk.set_widget_scaling(1.15) # aumentar un 15 % los widgets


# -- Errores propios -- #
class ErrorBoveda(Exception):  # error propio; hereda de Exception para poder usarse con raise/except
    """La bóveda está dañada o tiene un formato no compatible."""  # docstring: describe cuándo se lanza este error
class ErrorAutenticacion(ErrorBoveda):  # hereda de ErrorBoveda, así un "except ErrorBoveda" también lo captura
    """La contraseña maestra no permite descifrar la bóveda."""  # docstring: contraseña incorrecta


# ================================================================
# CIFRADO CON FERNET
# ================================================================
# Cómo funciona, paso a paso:
#   1. Contraseña maestra + sal  --scrypt-->  32 bytes  --base64-->  llave Fernet
#   2. Fernet(llave).encrypt(datos)  -->  "token" (texto ya cifrado y firmado)
#   3. En el archivo se guarda: la sal + el token
#   4. Para abrir: se repite el paso 1 con la sal guardada y Fernet(llave).decrypt(token)
# Fernet se encarga solo del IV aleatorio, de la firma (HMAC) y de la fecha, por eso
# aquí no hay que manejar nonce ni datos asociados.

def codificar_b64(valor: bytes) -> str:  # recibe bytes y devuelve texto (las anotaciones : y -> solo documentan los tipos)
    # Base64 convierte bytes a texto para poder guardarlos dentro del JSON.
    return base64.b64encode(valor).decode("ascii")  # b64encode da bytes en Base64; decode los pasa a str

def decodificar_b64(valor: str) -> bytes:  # recibe texto Base64 y devuelve bytes
    # Convierte el texto Base64 de nuevo a bytes y rechaza caracteres ajenos a Base64.
    return base64.b64decode(valor.encode("ascii"), validate=True)  # encode pasa el str a bytes; validate=True lanza error si hay caracteres inválidos

def derivar_llave_fernet(password, sal):  # convierte la contraseña maestra en una llave que Fernet pueda usar
    password = unicodedata.normalize("NFKC", password)  # normaliza el texto Unicode para que la misma contraseña siempre dé los mismos bytes
    # scrypt es lento a propósito: así probar muchas contraseñas es costoso para un atacante.
    # Parámetros fijos: n (costo de memoria/CPU), r (tamaño de bloque) y p (paralelismo).
    llave_bruta = Scrypt(salt=sal, length=32, n=2**18, r=8, p=1).derive(password.encode("utf-8"))  # 32 bytes derivados de la contraseña y la sal
    # Fernet exige que la llave de 32 bytes venga en Base64 "url-safe".
    return base64.urlsafe_b64encode(llave_bruta)  # esta es la llave final que se le pasa a Fernet(...)

def nuevos_parametros_kdf():  # crea los parámetros de la bóveda (solo la sal) para una bóveda nueva
    # La sal aleatoria evita que una misma contraseña produzca siempre la misma llave.
    return {"salt": codificar_b64(os.urandom(LARGO_SAL))}  # diccionario con una sal aleatoria en Base64

def cifrar_boveda(datos: dict, llave: bytes, parametros_kdf: dict):  # cifra el diccionario de la bóveda y devuelve los bytes a guardar en el archivo
    texto_plano = json.dumps(datos, ensure_ascii=False).encode("utf-8")  # diccionario → JSON → bytes (ensure_ascii=False conserva acentos y ñ)
    datos_cifrados = Fernet(llave).encrypt(texto_plano)  # Fernet cifra y firma; devuelve el "token" en bytes
    documento = dict(parametros_kdf)  # copia de los parámetros (la sal), para no modificar el original
    documento["formato"] = "fernet"  # etiqueta para reconocer el tipo de archivo al leerlo
    documento["datos_cifrados"] = datos_cifrados.decode("ascii")  # el token ya es texto Base64, solo se pasa de bytes a str
    return json.dumps(documento).encode("utf-8")  # devuelve el documento completo como bytes JSON

def cargar_boveda(ruta: Path, password: str):  # lee, valida y descifra la bóveda desde el archivo
    "Lee el archivo, valida su formato y lo descifra. Regresa (llave, parametros_kdf, datos)"  # docstring de la función
    try:  # primer bloque: lectura y validación del formato (sin descifrar aún)
        documento = json.loads(ruta.read_text(encoding="utf-8"))  # lee el archivo como texto y lo convierte de JSON a diccionario
        parametros_kdf = {"salt": documento["salt"]}  # extrae la sal; KeyError si falta
        datos_cifrados = documento["datos_cifrados"].encode("ascii")  # recupera el token de Fernet en bytes
        sal = decodificar_b64(parametros_kdf["salt"])  # recupera la sal en bytes
        if documento.get("formato") != "fernet":  # revisa que el formato sea el que la app entiende
            raise ValueError("Formato no compatible.")  # lanza error; lo captura el except de abajo
        if len(sal) != LARGO_SAL:  # revisa que la sal tenga el tamaño esperado
            raise ValueError("Longitud de sal inválida.")  # error por tamaño incorrecto
    except (OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError):  # atrapa cualquier problema de lectura o formato
        raise ErrorBoveda("La bóveda está dañada o no tiene un formato válido.")  # lo convierte en el error propio de la app

    try:  # segundo bloque: derivar la llave y descifrar
        # Se deriva la llave con la contraseña escrita y la sal guardada en el archivo.
        llave = derivar_llave_fernet(password, sal)  # los parámetros de scrypt son fijos dentro de la función
        # Si la contraseña es incorrecta o el archivo fue modificado, Fernet lanza InvalidToken.
        texto_plano = Fernet(llave).decrypt(datos_cifrados)  # verifica la firma y descifra
    except InvalidToken:  # contraseña incorrecta o archivo modificado
        raise ErrorAutenticacion()  # lanza el error de autenticación (sin mensaje)
    except (ValueError, MemoryError):  # parámetros inválidos o memoria insuficiente
        raise ErrorBoveda("No fue posible procesar los parámetros criptográficos de la bóveda.")  # error general de bóveda

    try:  # tercer bloque: interpretar el contenido descifrado
        datos = json.loads(texto_plano.decode("utf-8"))  # bytes → texto → diccionario
        if not isinstance(datos, dict):  # el contenido debe ser un diccionario
            raise ValueError()  # si no lo es, error
        datos.setdefault("settings", {})  # si falta "settings", lo crea vacío
        datos.setdefault("entries", {})  # si falta "entries", lo crea vacío
        return llave, parametros_kdf, datos  # devuelve una tupla con las tres cosas
    except (ValueError, UnicodeError, TypeError):  # contenido que no se pudo interpretar
        raise ErrorBoveda("El contenido descifrado no tiene una estructura válida.")  # error de estructura

def guardar_en_archivo_boveda(ruta: Path, contenido: bytes):  # guarda los bytes cifrados en disco de forma segura
    # Escribe primero en un archivo temporal y luego lo reemplaza, así nunca queda a medias
    ruta.parent.mkdir(parents=True, exist_ok=True)  # crea la carpeta si no existe (sin error si ya existe)
    temporal = ruta.with_suffix(".tmp")  # misma ruta pero con extensión .tmp
    with open(temporal, "wb") as archivo:  # abre el temporal en modo binario de escritura; "with" lo cierra solo
        archivo.write(contenido)  # escribe los bytes
        archivo.flush()  # vacía el búfer de Python hacia el sistema operativo
        os.fsync(archivo.fileno())  # obliga al sistema operativo a escribir realmente en disco
    os.replace(temporal, ruta)  # reemplazo atómico: el archivo final nunca queda a medias


# -- Utilidades generales -- #
def ahora_iso() -> str:  # devuelve la fecha y hora actual como texto
    return datetime.now().isoformat(timespec="seconds")  # formato ISO (2026-11-22T14:30:05) sin fracciones de segundo

def formato_fecha(valor: str) -> str:  # convierte una fecha ISO a formato legible
    try:  # intenta convertir
        return datetime.fromisoformat(valor).strftime("%d/%m/%Y %H:%M")  # texto ISO → fecha → "día/mes/año hora:minuto"
    except (ValueError, TypeError):  # valor inválido o None
        return "Fecha no disponible"  # texto de respaldo

def nueva_boveda() -> dict:  # estructura inicial de una bóveda vacía
    # Las llaves del diccionario ("settings", "entries", "site", "user"...) se quedan en inglés
    # porque ya están guardadas así dentro de las bóvedas existentes.
    return {"version": 2, "settings": {"autolock_min": 5}, "entries": {}}  # versión 2, bloqueo automático a 5 min y sin credenciales

def mostrar_mensaje(titulo: str, mensaje: str, icono="info"):  # atajo para mostrar una ventana de aviso
    CTkMessagebox(title=titulo, message=mensaje, icon=icono, sound=True)  # crea la ventana emergente con sonido

def confirmar(titulo: str, mensaje: str) -> bool:  # pregunta Sí/No y devuelve True o False
    respuesta = CTkMessagebox(title=titulo, message=mensaje, icon="question", option_1="No", option_2="Sí").get()  # .get() espera a que el usuario elija y devuelve el texto del botón
    return respuesta == "Sí"  # True solo si eligió "Sí"


def calcular_fuerza(password: str):  # estima la fortaleza de una contraseña
    "Estima la fuerza en bits de entropía. Regresa (bits, nivel, color, fracción de 0 a 1)"  # docstring con lo que devuelve
    if not password:  # si la contraseña está vacía
        return 0.0, "-", "#888888", 0.0  # devuelve valores neutros

    alfabeto = 0  # tamaño del conjunto de caracteres que usa la contraseña
    if any(c.islower() for c in password):  # ¿tiene alguna minúscula?
        alfabeto += 26  # suma las 26 letras minúsculas
    if any(c.isupper() for c in password):  # ¿tiene alguna mayúscula?
        alfabeto += 26  # suma las 26 mayúsculas
    if any(c.isdigit() for c in password):  # ¿tiene algún dígito?
        alfabeto += 10  # suma los 10 dígitos
    if any(not c.isalnum() for c in password):  # ¿tiene algún símbolo (carácter no alfanumérico)?
        alfabeto += 33  # suma aproximadamente 33 símbolos

    # Estimación teórica: longitud por log2 del tamaño del conjunto de caracteres posible.
    bits = len(password) * math.log2(max(alfabeto, 2))  # entropía = largo × log2(alfabeto); max evita log2 de 0 o 1

    # Penaliza si hay muchos caracteres repetidos
    # set() elimina duplicados; la proporción indica qué parte de la contraseña son caracteres distintos.
    proporcion_unicos = len(set(password)) / len(password)  # caracteres distintos ÷ largo total
    if proporcion_unicos < 0.7:  # si hay muchas repeticiones
        bits *= max(proporcion_unicos, 0.4)  # reduce los bits, con un piso de 0.4 para no penalizar de más

    # Penaliza secuencias de tres caracteres consecutivos (abc, 123, cba)
    # zip crea grupos de tres caracteres consecutivos; ord() permite comparar sus códigos.
    secuencias = sum(1 for a, b, c in zip(password, password[1:], password[2:]) if abs(ord(b) - ord(a)) == 1 and ord(b) - ord(a) == ord(c) - ord(b))  # cuenta tríos donde cada carácter sube o baja 1 respecto al anterior
    bits = max(bits - 6 * secuencias, 0)  # resta 6 bits por cada secuencia, sin bajar de 0

    comunes = {"password", "123456", "12345678", "123456789", "12345", "qwerty", "qwerty123", "abc123", "111111", "000000", "admin", "letmein", "iloveyou", "welcome", "password1", "contraseña", "contrasena", "1q2w3e4r", "monkey", "dragon", "hola"}  # conjunto de contraseñas muy comunes
    if password.casefold() in comunes:  # casefold ignora mayúsculas/minúsculas
        bits = min(bits, 10)  # si es común, limita los bits a 10 como máximo

    niveles = [  # lista de umbrales: (límite de bits, nombre del nivel, color)
        (28, "Muy débil", ERROR),  # menos de 28 bits
        (40, "Débil", ADVERTENCIA),  # de 28 a menos de 40
        (60, "Media", "#B38A16"),  # de 40 a menos de 60
        (80, "Fuerte", EXITO),  # de 60 a menos de 80
        (float("inf"), "Muy fuerte", SUPREMO),  # infinito: cualquier valor restante
    ]  # fin de la lista de niveles
    # Desempaqueta cada tupla y selecciona el primer umbral que supera los bits calculados.
    for limite, nivel, color in niveles:  # recorre los niveles de menor a mayor
        if bits < limite:  # el primer umbral que los bits no alcanzan define el nivel
            return bits, nivel, color, min(bits / 100, 1.0)  # fracción para la barra: bits/100, máximo 1.0
    return bits, "Muy fuerte", SUPREMO, 1.0  # respaldo; en la práctica el umbral infinito siempre se cumple antes


def crear_password(largo: int, mayusculas: bool, digitos: bool, simbolos: bool):  # genera una contraseña aleatoria
    # Usa "secrets" (no "random") porque es el módulo pensado para valores de seguridad
    grupos = [string.ascii_lowercase]  # lista de grupos de caracteres; las minúsculas siempre van
    if mayusculas:  # si se pidieron mayúsculas
        grupos.append(string.ascii_uppercase)  # agrega el grupo A-Z
    if digitos:  # si se pidieron números
        grupos.append(string.digits)  # agrega 0-9
    if simbolos:  # si se pidieron símbolos
        grupos.append(string.punctuation)  # agrega los signos de puntuación

    if largo < len(grupos):  # no cabe un carácter de cada grupo
        raise ValueError("La longitud no alcanza para incluir los tipos de caracteres seleccionados.")  # error con mensaje para el usuario

    caracteres_totales = "".join(grupos)  # junta todos los grupos en un solo texto para elegir al azar
    # Elige primero un carácter de cada grupo activado para garantizar que todos estén presentes.
    caracteres = [secrets.choice(grupo) for grupo in grupos]  # al menos uno de cada tipo
    # Completa las posiciones restantes eligiendo al azar entre todos los caracteres permitidos.
    caracteres.extend(secrets.choice(caracteres_totales) for _ in range(largo - len(caracteres)))  # agrega los que faltan; "_" indica que la variable no se usa

    # Mezcla (Fisher-Yates) para que los obligatorios no queden siempre al inicio
    # Fisher-Yates mezcla la lista recorriéndola de atrás hacia delante.
    for i in range(len(caracteres) - 1, 0, -1):  # i va desde el último índice hasta 1
        j = secrets.randbelow(i + 1)  # número aleatorio seguro de 0 a i
        caracteres[i], caracteres[j] = caracteres[j], caracteres[i]  # intercambio de dos posiciones en una sola línea
    return "".join(caracteres)  # une la lista de caracteres en un texto


def validar_nueva_maestra(maestra: str, confirmacion: str):  # valida una contraseña maestra nueva; devuelve un mensaje de error o None
    if maestra != confirmacion:  # las dos entradas deben ser iguales
        return "Las contraseñas maestras no coinciden."  # mensaje de error
    if len(maestra) < MASTER_MIN_LARGO or calcular_fuerza(maestra)[0] < MASTER_MIN_BITS:  # muy corta o con pocos bits (el [0] toma solo los bits de la tupla)
        return f"La contraseña maestra debe tener al menos {MASTER_MIN_LARGO} caracteres y no ser trivial. Se recomienda utilizar una frase larga."  # f-string que inserta el mínimo
    return None  # None significa "sin errores"


# --- Aplicación Principal Gestor --- #
class Aplicacion(ctk.CTk):  # la ventana principal; hereda de ctk.CTk, así que ES una ventana de customtkinter
    def __init__(self):  # constructor: se ejecuta al crear la aplicación
        super().__init__()  # inicializa la parte de ctk.CTk (crea la ventana)
        self.title("Gestor local de contraseñas | MISTI - IPN")  # texto de la barra de título
        self.geometry("1120x790")  # tamaño inicial: ancho x alto en píxeles
        self.minsize(980, 700)  # tamaño mínimo al que se puede reducir la ventana

        self.tema_actual = "Light"  # la app principal inicia en claro, el login siempre en oscuro
        ctk.set_appearance_mode("Light")  # arranca en oscuro porque lo primero que se ve es el login

        self.llave = None  # llave Fernet de la sesión (None = bóveda bloqueada)
        self.parametros_kdf = None  # parámetros de la bóveda abierta (la sal)
        self.boveda = None  # diccionario con los datos descifrados
        self.id_seleccionado = None  # ID de la credencial elegida en la lista

        self.intentos_fallidos = 0  # contador de contraseñas maestras incorrectas
        self.bloqueado_hasta = 0.0  # instante (reloj monotónico) hasta el que el login está bloqueado
        self.ultima_actividad = time.monotonic()  # momento de la última acción del usuario; monotonic no se ve afectado por cambios de hora del sistema

        self.contenedor = ctk.CTkFrame(self, fg_color="transparent")  # marco que contiene cada ventana que se ve, sea gestor o login
        self.contenedor.pack(fill="both", expand=True)  # lo extiende para ocupar toda la ventana

        # Cualquier tecla, clic o movimiento cuenta como actividad (para el bloqueo automático)
        for evento in ("<Key>", "<Button>", "<Motion>"):  # tecla, clic y movimiento del mouse
            # bind_all escucha el evento en cualquier widget; add="+" conserva otros manejadores.
            self.bind_all(evento, self.registrar_actividad, add="+")  # cada vez que ocurre, se llama a registrar_actividad

        self.protocol("WM_DELETE_WINDOW", self.cerrar_aplicacion)  # al pulsar la X de la ventana se ejecuta cerrar_aplicacion
        self.construir_login()  # muestra la pantalla de inicio de sesión
        self.after(1000, self.vigilar_inactividad)  # after(ms, función): ejecuta la función tras 1000 ms


    # APARIENCIA Y UTILIDADES GENERALES
    # ================================================================
    def cambiar_tema(self, seleccion):  # se llama cuando el usuario elige un tema en el menú
        tema = {"Claro": "Light", "Oscuro": "Dark"}.get(seleccion, "Light")  # traduce el texto del menú al nombre que usa ctk; "Light" si no coincide
        self.tema_actual = tema  # recuerda el tema elegido
        ctk.set_appearance_mode(tema)  # aplica el tema a toda la interfaz

    def menu_tema(self, padre):  # construye el selector de tema dentro del widget "padre"
        marco = ctk.CTkFrame(padre, fg_color="transparent")  # marco transparente que agrupa etiqueta y menú
        ctk.CTkLabel(marco, text="Tema:").pack(side="left", padx=(0, 7))  # etiqueta "Tema:" a la izquierda con 7 px de espacio a su derecha
        menu = ctk.CTkOptionMenu(marco, values=["Oscuro", "Claro"], command=self.cambiar_tema, width=105, fg_color=GUINDA, button_color=GUINDA, button_hover_color=GUINDA_HOVER)  # menú desplegable; command recibe la opción elegida
        menu.set("Claro" if self.tema_actual == "Light" else "Oscuro")  # muestra seleccionada la opción del tema actual
        menu.pack(side="left")  # coloca el menú junto a la etiqueta
        return marco  # devuelve el marco para que quien llama lo coloque (con .pack)

    def limpiar_pantalla(self):  # borra todo lo que hay en pantalla antes de dibujar otra
        for hijo in self.contenedor.winfo_children():  # lista de widgets hijos del contenedor
            hijo.destroy()  # elimina cada uno

    def pie_pagina(self, padre):  # dibuja la franja guinda inferior con los logos
        "Pie institucional guinda, compartido por el login y la aplicación"  # docstring de la función
        pie = ctk.CTkFrame(padre, fg_color=GUINDA, corner_radius=0, height=76)  # marco guinda de 76 px de alto y sin esquinas redondeadas
        pie.pack(side="bottom", fill="x")  # lo pega abajo y lo estira a lo ancho
        pie.pack_propagate(False)  # evita que el marco cambie su tamaño según su contenido
        interior = ctk.CTkFrame(pie, fg_color="transparent")  # marco interior para centrar los elementos
        interior.pack(expand=True)  # expand=True lo centra dentro del pie

        marco_ipn = ctk.CTkFrame(interior, fg_color="transparent", width=53, height=61)  # espacio de tamaño fijo para el logo del IPN
        marco_ipn.pack(side="left", padx=(4, 8))  # a la izquierda, con 4 px a un lado y 8 al otro
        marco_ipn.pack_propagate(False)  # mantiene el tamaño fijo
        self.agregar_logo_imagen(marco_ipn, LOGO_IPN, (40, 53))  # pone el logo del IPN con tamaño 40x53
        ctk.CTkLabel(interior, text="INSTITUTO POLITÉCNICO NACIONAL", font=ctk.CTkFont(size=11, weight="bold"), text_color="#FFFFFF").pack(side="left", padx=(0, 22))  # texto institucional en blanco y negritas
        self.agregar_logo_imagen(interior, LOGO_MISTI, (48, 48))  # logo de MISTI de 48x48
        ctk.CTkLabel(interior, text="MAESTRÍA EN INGENIERÍA EN SEGURIDAD\nY TECNOLOGÍAS DE LA INFORMACIÓN", font=ctk.CTkFont(size=10, weight="bold"), text_color="#FFFFFF", justify="left").pack(side="left", padx=8)  # nombre de la maestría en dos líneas (\n = salto de línea)

    def agregar_logo_imagen(self, padre, ruta, tamano, centrar=False):  # coloca una imagen dentro de "padre"
        if not ruta.exists():  # si el archivo de imagen no existe
            return  # sale sin hacer nada
        try:  # intenta cargar la imagen
            from PIL import Image  # importa Pillow aquí dentro, solo cuando se necesita
            imagen = ctk.CTkImage(light_image=Image.open(ruta), dark_image=Image.open(ruta), size=tamano)  # imagen compatible con ctk (la misma para tema claro y oscuro)
            etiqueta = ctk.CTkLabel(padre, text="", image=imagen)
            if centrar:
                etiqueta.place(relx=0.5, rely=0.5, anchor="center")  # centro exacto del panel
            else:  # logos del pie, igual que antes
                etiqueta.pack(side="left", padx=4)
        except Exception:  # cualquier fallo al cargarla
            # La aplicación debe iniciar aunque falte Pillow o la imagen sea inválida
            pass  # ignora el error y sigue

    def registrar_actividad(self, _evento=None):  # guarda el momento de la última actividad del usuario
        self.ultima_actividad = time.monotonic()  # actualiza la marca de tiempo; _evento lo manda tkinter pero aquí no se usa


    # CONSTRUCCIÓN DE INTERFACES
    # ================================================================
    def construir_login(self, mensaje=""):  # dibuja la pantalla de login; "mensaje" es un aviso opcional
        self.limpiar_pantalla()  # borra la pantalla anterior
        ctk.set_appearance_mode("Dark")  # el login siempre usa el tema oscuro

        self.pie_pagina(self.contenedor)  # agrega el pie guinda (se empaqueta primero para quedar abajo)
        centro = ctk.CTkFrame(self.contenedor, fg_color="transparent")  # marco central que alojará los dos paneles
        centro.pack(fill="both", expand=True, padx=34, pady=18)  # ocupa el espacio restante con márgenes

        # Dos paneles: izquierda la imagen, derecha el formulario
        centro.grid_columnconfigure(0, weight=11, uniform="login")  # columna 0 con peso 11; uniform hace que los pesos se respeten proporcionalmente
        centro.grid_columnconfigure(1, weight=13, uniform="login")  # columna 1 con peso 13 (un poco más ancha)
        centro.grid_rowconfigure(0, weight=1)  # la única fila crece para llenar la altura

        # -- Panel izquierdo con la imagen ascii -- #
        self.panel_imagen_login = ctk.CTkFrame(centro, fg_color="black", corner_radius=18, border_width=1, border_color=GUINDA)  # panel negro con esquinas redondeadas y borde
        self.panel_imagen_login.grid(row=0, column=0, sticky="nsew", padx=(0, 10))  # lo ubica en fila 0, columna 0; sticky="nsew" lo estira en las 4 direcciones
        self.lienzo_imagen_login = ctk.CTkCanvas(self.panel_imagen_login, bg="black", highlightthickness=0)  # lienzo donde se dibuja la galaxia; sin borde de enfoque
        self.lienzo_imagen_login.pack(fill="both", expand=True, padx=8, pady=8)  # el lienzo llena el panel con un margen de 8 px
        self.agregar_logo_imagen(self.panel_imagen_login, IMAGEN_LOGIN, (390, 560), centrar=True)  # espera 150 ms a que la ventana tenga tamaño y arranca la animación

        # -- Panel derecho con el formulario -- #
        panel_login = ctk.CTkFrame(centro, fg_color=PANEL, corner_radius=18, border_width=1, border_color=GUINDA)  # panel del formulario
        panel_login.grid(row=0, column=1, sticky="nsew", padx=(10, 0))  # fila 0, columna 1, estirado en todas direcciones
        ctk.CTkLabel(panel_login, text="Gestor de contraseñas", font=ctk.CTkFont(size=25, weight="bold"), text_color=TEXTO).pack(pady=(26, 3))  # título grande
        ctk.CTkLabel(panel_login, text="Almacenamiento y cifrado local", text_color=NEUTRO).pack(pady=(0, 8))  # subtítulo en gris
        self.mensaje_login = ctk.CTkLabel(panel_login, text=mensaje, text_color=ADVERTENCIA, wraplength=420, justify="center")  # etiqueta de avisos; wraplength parte el texto en líneas de 420 px
        self.mensaje_login.pack(padx=20, pady=(0, 5))  # la coloca bajo el subtítulo

        pestanas = ctk.CTkTabview(panel_login, width=440, height=475, segmented_button_selected_color=GUINDA, segmented_button_selected_hover_color=GUINDA_HOVER)  # contenedor con pestañas; la pestaña seleccionada se ve guinda
        pestanas.pack(fill="both", expand=True, padx=22, pady=(4, 22))  # lo extiende dentro del panel

        # Si ya existe la bóveda se pide la contraseña maestra; si no, se crea una nueva
        if RUTA_BOVEDA.exists():  # ¿ya hay un archivo de bóveda?
            self.construir_pestana_login(pestanas.add("Desbloquear"))  # add crea la pestaña y devuelve su marco; ahí se arma el formulario de desbloqueo
        else:  # si no existe
            self.construir_pestana_crear(pestanas.add("Crear bóveda"))  # pestaña para crear la bóveda
        self.construir_pestana_info(pestanas.add("Información de uso"))  # siempre se agrega la pestaña de información

    def construir_pestana_login(self, pestana):  # formulario para desbloquear la bóveda
        ctk.CTkLabel(pestana, text="Contraseña maestra").pack(anchor="w", padx=18, pady=(40, 5))  # etiqueta alineada al oeste (izquierda)
        self.login_maestra = ctk.CTkEntry(pestana, height=38, show="*", placeholder_text="Contraseña maestra")  # campo de texto; show="*" oculta lo escrito
        self.login_maestra.pack(fill="x", padx=18)  # se estira a lo ancho

        self.mostrar_login = ctk.BooleanVar(value=False)  # variable booleana ligada a la casilla (False = oculta)
        ctk.CTkCheckBox(pestana, text="Mostrar contraseña", variable=self.mostrar_login, command=lambda: self.login_maestra.configure(show="" if self.mostrar_login.get() else "*"), checkbox_width=18, checkbox_height=18).pack(anchor="w", padx=18, pady=13)  # al marcarla, la lambda quita o pone el "*" del campo

        self.boton_login = ctk.CTkButton(pestana, text="Desbloquear", height=42, command=self.iniciar_sesion, **BOTON_GUINDA)  # botón que llama a iniciar_sesion; ** aplica el estilo guinda
        self.boton_login.pack(fill="x", padx=18, pady=(16, 8))  # lo coloca a lo ancho
        ctk.CTkLabel(pestana, text="La bóveda permanece almacenada en este equipo.", text_color=NEUTRO, font=ctk.CTkFont(size=11)).pack(pady=10)  # nota informativa

        self.login_maestra.bind("<Return>", lambda _evento: self.iniciar_sesion())  # al presionar Enter dentro del campo, intenta iniciar sesión
        # Deja el cursor listo en el campo de contraseña
        self.after(300, lambda: self.login_maestra.winfo_exists() and self.login_maestra.focus_set())  # tras 300 ms enfoca el campo, solo si todavía existe (el "and" evita errores si ya se destruyó)


    def construir_pestana_crear(self, pestana):  # formulario para crear la bóveda por primera vez
        self.var_nueva_maestra = ctk.StringVar()  # variable de texto ligada al campo de la contraseña nueva
        self.var_confirmar_maestra = ctk.StringVar()  # variable de texto ligada al campo de confirmación

        ctk.CTkLabel(pestana, text="Aún no existe una bóveda. Cree su contraseña maestra y recuérdela: no existe un mecanismo de recuperación.", text_color=ADVERTENCIA, wraplength=390, justify="left").pack(anchor="w", padx=18, pady=(12, 12))  # advertencia de que la maestra no se puede recuperar
        ctk.CTkLabel(pestana, text=f"Contraseña maestra (mínimo {MASTER_MIN_LARGO} caracteres)").pack(anchor="w", padx=18)  # etiqueta que muestra el mínimo con un f-string
        self.entrada_nueva_maestra = ctk.CTkEntry(pestana, height=36, show="*", textvariable=self.var_nueva_maestra)  # campo oculto ligado a su variable
        self.entrada_nueva_maestra.pack(fill="x", padx=18, pady=(3, 10))  # lo coloca a lo ancho
        ctk.CTkLabel(pestana, text="Confirmar contraseña maestra").pack(anchor="w", padx=18)  # etiqueta del segundo campo
        self.entrada_confirmar_maestra = ctk.CTkEntry(pestana, height=36, show="*", textvariable=self.var_confirmar_maestra)  # campo de confirmación
        self.entrada_confirmar_maestra.pack(fill="x", padx=18, pady=(3, 10))  # lo coloca a lo ancho

        self.mostrar_nueva = ctk.BooleanVar(value=False)  # variable de la casilla "mostrar"
        ctk.CTkCheckBox(pestana, text="Mostrar contraseñas", variable=self.mostrar_nueva, command=self.alternar_nueva_password).pack(anchor="w", padx=18, pady=5)  # al marcarla llama a alternar_nueva_password

        fila_fuerza = ctk.CTkFrame(pestana, fg_color="transparent")  # fila que agrupa la etiqueta, la barra y el texto de fuerza
        fila_fuerza.pack(fill="x", padx=18, pady=8)  # la coloca a lo ancho
        ctk.CTkLabel(fila_fuerza, text="Fuerza").pack(side="left")  # etiqueta "Fuerza" a la izquierda
        self.barra_maestra = ctk.CTkProgressBar(fila_fuerza, progress_color=NEUTRO)  # barra de progreso gris al inicio
        self.barra_maestra.set(0)  # la barra empieza vacía (valor entre 0 y 1)
        self.barra_maestra.pack(side="left", fill="x", expand=True, padx=9)  # la barra ocupa el espacio sobrante
        self.etiqueta_maestra = ctk.CTkLabel(fila_fuerza, text="-", width=150)  # texto con el nivel; "-" cuando no hay nada escrito
        self.etiqueta_maestra.pack(side="left")  # a la derecha de la barra

        # trace_add ejecuta la actualización cada vez que cambia el contenido de esta variable.
        self.var_nueva_maestra.trace_add("write", lambda *_: self.actualizar_fuerza_maestra())  # cada vez que se escribe, se recalcula la fuerza; *_ ignora los argumentos que manda trace_add
        ctk.CTkButton(pestana, text="Crear bóveda", height=40, command=self.crear_boveda, **BOTON_GUINDA).pack(fill="x", padx=18, pady=13)  # botón que llama a crear_boveda


    def construir_pestana_info(self, pestana):  # pestaña con información de uso
        ctk.CTkLabel(pestana, text="Acerca del gestor", font=ctk.CTkFont(size=19, weight="bold")).pack(anchor="w", padx=18, pady=(14, 3))  # título de la pestaña
        ctk.CTkLabel(pestana, text="Administración local y segura de credenciales.", text_color=NEUTRO, font=ctk.CTkFont(size=11)).pack(anchor="w", padx=18, pady=(0, 10))  # subtítulo en gris

        # Área con desplazamiento donde van los apartados
        info = ctk.CTkScrollableFrame(pestana, fg_color="transparent")  # marco con barra de desplazamiento
        info.pack(fill="both", expand=True, padx=10, pady=(0, 8))  # llena el espacio disponible

        secciones = [  # lista de tuplas (título, descripción)
            ("1. ¿Qué es esta aplicación?", "Es un gestor local de contraseñas que permite generar, almacenar, consultar y administrar credenciales desde una bóveda protegida."),  # sección 1
            ("2. Generador de contraseñas", "Permite crear contraseñas aleatorias y personalizables. Se puede configurar su longitud y elegir si incluye letras mayúsculas, números y símbolos. También incorpora un indicador estimado de fortaleza."),  # sección 2
            ("3. Bóveda de credenciales", "Permite guardar el sitio o servicio, nombre de usuario, correo electrónico y contraseña. Las credenciales pueden consultarse, copiarse, actualizarse y eliminarse."),  # sección 3
            ("4. Protección criptográfica", "La información se almacena cifrada mediante Fernet (AES-128-CBC con firma HMAC-SHA256). La contraseña maestra se procesa con scrypt para derivar la llave de cifrado. Cada operación de cifrado utiliza un vector de inicialización (IV) aleatorio."),  # sección 4
            ("5. Herramientas adicionales", "Incluye historial de contraseñas anteriores, detección local de contraseñas reutilizadas, auditoría de fortaleza y bloqueo automático por inactividad."),  # sección 5
            ("6. Funcionamiento local", "La aplicación no necesita conexión a Internet. La bóveda se almacena en el equipo, dentro de la carpeta local 'boveda'. Solo existe una bóveda, protegida por una única contraseña maestra."),  # sección 6
            ("7. Consideraciones de seguridad", "La contraseña maestra no puede recuperarse. Si se pierde, no será posible acceder a la bóveda. La auditoría no consulta bases de datos externas ni detecta contraseñas filtradas en Internet."),  # sección 7
        ]  # fin de la lista de secciones

        for titulo, descripcion in secciones:  # recorre cada tupla, desempaquetándola en dos variables
            seccion = ctk.CTkFrame(info, fg_color=PANEL, corner_radius=9, border_width=1, border_color=BORDE)  # tarjeta de la sección
            seccion.pack(fill="x", padx=5, pady=5)  # la coloca a lo ancho
            ctk.CTkLabel(seccion, text=titulo, font=ctk.CTkFont(size=15, weight="bold"), text_color="white", anchor="w").pack(fill="x", padx=11, pady=(9, 3))  # título en guinda y negritas
            ctk.CTkLabel(seccion, text=descripcion, font=ctk.CTkFont(size=12), text_color=TEXTO, justify="left", anchor="w", wraplength=405).pack(fill="x", padx=11, pady=(0, 10))  # descripción con saltos de línea automáticos a 365 px

        ctk.CTkLabel(pestana, text="Aplicación desarrollada por: Del Castillo Camacho Osvaldo Ulrick y Téllez Hernandez Daniel", text_color=NEUTRO, font=ctk.CTkFont(size=10, weight="bold")).pack(pady=(2, 8))  # créditos de los autores


    def construir_principal(self):  # dibuja la pantalla principal (con la bóveda ya abierta)
        self.limpiar_pantalla()  # borra el login
        ctk.set_appearance_mode(self.tema_actual)  # aplica el tema que eligió el usuario (claro por defecto)

        arriba = ctk.CTkFrame(self.contenedor, fg_color="transparent")  # barra superior
        arriba.pack(fill="x", padx=18, pady=(12, 5))  # a lo ancho, con márgenes
        titulo = ctk.CTkFrame(arriba, fg_color="transparent")  # marco para el título
        titulo.pack(side="left", anchor="w")  # a la izquierda de la barra
        ctk.CTkLabel(titulo, text="Gestor local de contraseñas", font=ctk.CTkFont(size=19, weight="bold"), text_color=TEXTO).pack(anchor="w")  # título principal

        controles = ctk.CTkFrame(arriba, fg_color="transparent")  # marco para los controles de la derecha
        controles.pack(side="right", anchor="e")  # a la derecha de la barra
        self.menu_tema(controles).pack(side="left", padx=(0, 12))  # crea el selector de tema y lo coloca (menu_tema devuelve el marco)
        ctk.CTkButton(controles, text="Bloquear", width=100, height=32, command=self.bloquear_boveda, **BOTON_GUINDA).pack(side="left", padx=(0, 10))  # botón para bloquear la bóveda manualmente
        ctk.CTkLabel(controles, text="Bloqueo automático:", text_color=NEUTRO).pack(side="left", padx=(0, 6))  # etiqueta del menú de autobloqueo
        self.opciones_bloqueo = {"1 minuto": 1, "2 minutos": 2, "5 minutos": 5, "10 minutos": 10, "15 minutos": 15, "30 minutos": 30}  # diccionario texto del menú → minutos
        self.menu_bloqueo = ctk.CTkOptionMenu(controles, values=list(self.opciones_bloqueo), command=self.cambiar_autobloqueo, width=115, fg_color=GUINDA, button_color=GUINDA, button_hover_color=GUINDA_HOVER)  # menú con las llaves del diccionario (list(dict) da sus llaves)
        minutos = int(self.boveda["settings"].get("autolock_min", 5))  # lee los minutos guardados en la bóveda (5 por defecto)
        self.menu_bloqueo.set(next((nombre for nombre, valor in self.opciones_bloqueo.items() if valor == minutos), "5 minutos"))  # busca el texto cuyo valor coincide con los minutos; si no hay, usa "5 minutos"
        self.menu_bloqueo.pack(side="left")  # coloca el menú

        self.pie_pagina(self.contenedor)  # agrega el pie guinda
        cuerpo = ctk.CTkFrame(self.contenedor, fg_color="transparent")  # marco del contenido central
        cuerpo.pack(fill="both", expand=True, padx=14, pady=8)  # ocupa el espacio restante
        cuerpo.grid_columnconfigure(0, weight=6)  # columna izquierda con peso 6
        cuerpo.grid_columnconfigure(1, weight=5)  # columna derecha con peso 5
        cuerpo.grid_rowconfigure(0, weight=1)  # la fila crece a lo alto

        frame_izquierdo = ctk.CTkFrame(cuerpo, fg_color="transparent")  # columna del generador
        frame_izquierdo.grid(row=0, column=0, sticky="nsew", padx=(0, 8))  # fila 0, columna 0
        frame_derecha = ctk.CTkFrame(cuerpo, fg_color=PANEL, corner_radius=14, border_width=1, border_color=BORDE, width=365)  # columna de la bóveda, con aspecto de panel
        frame_derecha.grid(row=0, column=1, sticky="nsew", padx=(8, 0))  # fila 0, columna 1
        frame_derecha.grid_propagate(False)  # evita que el panel cambie de tamaño según su contenido

        self.construir_generador(frame_izquierdo)  # llena la columna izquierda
        self.construir_panel_boveda(frame_derecha)  # llena la columna derecha


    def construir_generador(self, padre):  # arma el generador de contraseñas y el formulario de guardado
        # -- Variables de estado para la interfaz -- #
        self.var_largo = ctk.IntVar(value=12)  # longitud de la contraseña (empieza en 12)
        self.var_upper = ctk.BooleanVar(value=True)  # ¿incluir mayúsculas?
        self.var_digitos = ctk.BooleanVar(value=True)  # ¿incluir números?
        self.var_symbols = ctk.BooleanVar(value=True)  # ¿incluir símbolos?
        self.var_show = ctk.BooleanVar(value=False)  # ¿mostrar la contraseña en pantalla?
        self.var_password = ctk.StringVar(value="")  # texto de la contraseña actual
        self.var_sitio_web = ctk.StringVar()  # texto del campo sitio o servicio
        self.var_usuario = ctk.StringVar()  # texto del campo usuario
        self.var_correo = ctk.StringVar()  # texto del campo correo

        # -- Opciones -- #
        frame_de_opciones = ctk.CTkFrame(padre, fg_color=PANEL, corner_radius=14, border_width=1, border_color=BORDE)  # tarjeta de opciones
        frame_de_opciones.pack(fill="x", pady=(0, 10))  # a lo ancho, con espacio abajo
        ctk.CTkLabel(frame_de_opciones, text="Generador de contraseñas", font=ctk.CTkFont(size=17, weight="bold")).pack(anchor="w", padx=15, pady=(12, 7))  # título de la tarjeta

        fila_largo = ctk.CTkFrame(frame_de_opciones, fg_color="transparent")  # fila del control de longitud de la contraseña a generar
        fila_largo.pack(fill="x", padx=14, pady=6)  # el ancho y padding
        ctk.CTkLabel(fila_largo, text="Longitud").pack(side="left")  # etiqueta "Longitud"
        self.scale = ctk.CTkSlider(fila_largo, from_=PASSWORD_MIN_LARGO, to=64, number_of_steps=64 - PASSWORD_MIN_LARGO, command=self.scale_de_fuerza, progress_color=GUINDA, button_color=GUINDA, button_hover_color=GUINDA_HOVER)  # deslizador de 8 a 64 con un paso por cada número entero; command se ejecuta al moverlo
        self.scale.set(self.var_largo.get())  # coloca el deslizador en el valor inicial (12)
        self.scale.pack(side="left", fill="x", expand=True, padx=10)  # ocupa el espacio sobrante
        ctk.CTkLabel(fila_largo, textvariable=self.var_largo, width=28).pack(side="left")  # muestra el número actual (se actualiza solo por textvariable)

        fila_de_botones = ctk.CTkFrame(frame_de_opciones, fg_color="transparent")  # fila de las casillas
        fila_de_botones.pack(fill="x", padx=14, pady=(3, 12))  # a lo ancho
        for txt, var in [("Mayúsculas", self.var_upper), ("Números", self.var_digitos), ("Símbolos", self.var_symbols)]:  # recorre pares (texto, variable)
            ctk.CTkCheckBox(fila_de_botones, text=txt, variable=var).pack(side="left", padx=(0, 16))  # crea una casilla por cada par

        # -- Resultado y almacenamiento -- #
        frame_resultado = ctk.CTkFrame(padre, fg_color=PANEL, corner_radius=14, border_width=1, border_color=BORDE)  # tarjeta de resultado
        frame_resultado.pack(fill="both", expand=True)  # ocupa el resto del espacio
        ctk.CTkLabel(frame_resultado, text="Resultado y almacenamiento", font=ctk.CTkFont(size=17, weight="bold")).pack(anchor="w", padx=15, pady=(12, 8))  # título de la tarjeta

        fila_password = ctk.CTkFrame(frame_resultado, fg_color="transparent")  # fila del campo de contraseña
        fila_password.pack(fill="x", padx=12, pady=5)  # a lo ancho
        self.entrada = ctk.CTkEntry(fila_password, textvariable=self.var_password, show="*", font=("Consolas", 14), height=38)  # campo de la contraseña, oculto y con fuente monoespaciada
        self.entrada.pack(side="left", fill="x", expand=True)  # ocupa el espacio sobrante
        ctk.CTkCheckBox(fila_password, text="Mostrar", variable=self.var_show, command=self.alternar_mostrar_caracteres).pack(side="left", padx=8)  # casilla que muestra u oculta el texto
        ctk.CTkButton(fila_password, text="Copiar", width=78, command=self.copiar_password, **BOTON_GRIS).pack(side="left")  # botón de copiar

        # -- Barra de fortaleza -- #
        frame_fortaleza = ctk.CTkFrame(frame_resultado, fg_color="transparent")  # fila de la barra de fuerza
        frame_fortaleza.pack(fill="x", padx=13, pady=(12, 5))  # a lo ancho
        ctk.CTkLabel(frame_fortaleza, text="Fuerza estimada:", width=65, anchor="w").pack(side="left")  # etiqueta con ancho fijo
        self.barra_progreso = ctk.CTkProgressBar(frame_fortaleza, progress_color=NEUTRO)  # barra de fuerza
        self.barra_progreso.set(0)  # empieza vacía
        self.barra_progreso.pack(side="left", fill="x", expand=True, padx=8)  # ocupa el espacio sobrante
        self.etiquetas = ctk.CTkLabel(frame_fortaleza, text="-", width=125)  # texto con nivel y bits
        self.etiquetas.pack(side="left")  # a la derecha de la barra

        frame_botones_password = ctk.CTkFrame(frame_resultado, fg_color="transparent")  # fila de botones Generar y Limpiar
        frame_botones_password.pack(fill="x", padx=12, pady=(3, 8))  # a lo ancho
        ctk.CTkButton(frame_botones_password, text="Generar", command=self.generar_password, **BOTON_GRIS).pack(side="left")  # genera una contraseña nueva
        ctk.CTkButton(frame_botones_password, text="Limpiar", command=self.limpiar_campos, **BOTON_GRIS).pack(side="left", padx=8)  # vacía los campos

        self.etiqueta_estado = ctk.CTkLabel(frame_resultado, text="", anchor="w", justify="left", wraplength=600, text_color=ADVERTENCIA)  # etiqueta para avisos (por ejemplo, contraseña reutilizada)
        self.etiqueta_estado.pack(fill="x", padx=14, pady=(0, 5))  # a lo ancho

        # -- Sitio, usuario y correo (el asterisco rojo marca los obligatorios) -- #
        # Aquí "usuario" es el nombre de usuario de la cuenta guardada (por ejemplo, en un sitio web)
        for texto, variable, obligatorio in (("Sitio o servicio:", self.var_sitio_web, True), ("Usuario:", self.var_usuario, True), ("Correo (opcional):", self.var_correo, False)):  # recorre tuplas (texto, variable, ¿obligatorio?) para crear las 3 filas con el mismo código
            fila = ctk.CTkFrame(frame_resultado, fg_color="transparent")  # fila del campo
            fila.pack(fill="x", padx=13, pady=4)  # a lo ancho
            marco_texto = ctk.CTkFrame(fila, fg_color="transparent", width=145, height=28)  # espacio de ancho fijo para la etiqueta, así los campos quedan alineados
            marco_texto.pack(side="left")  # a la izquierda
            marco_texto.pack_propagate(False)  # mantiene el tamaño fijo
            ctk.CTkLabel(marco_texto, text=texto, anchor="w").pack(side="left")  # texto de la etiqueta
            if obligatorio:  # solo si el campo es obligatorio
                ctk.CTkLabel(marco_texto, text="*", text_color="#E53935", font=ctk.CTkFont(size=15, weight="bold")).pack(side="left", padx=(3, 0))  # asterisco rojo
            ctk.CTkEntry(fila, textvariable=variable, height=35).pack(side="left", fill="x", expand=True)  # campo de texto ligado a su variable

        ctk.CTkButton(frame_resultado, text="Guardar en bóveda", height=40, command=self.salvar_entrada, **BOTON_GUINDA).pack(anchor="w", padx=13, pady=(10, 14))  # botón que guarda la credencial

        # Actualiza la barra automáticamente cada vez que cambia la contraseña escrita.
        self.var_password.trace_add("write", lambda *_: self.actualizar_fuerza())  # cada cambio en la contraseña recalcula la barra
        self.actualizar_fuerza()  # la calcula una vez al iniciar


    def construir_panel_boveda(self, padre):  # arma el panel derecho con la lista de credenciales
        ctk.CTkLabel(padre, text="Bóveda de credenciales", font=ctk.CTkFont(size=17, weight="bold")).pack(anchor="w", padx=13, pady=(13, 8))  # título del panel
        self.entrada_filtro = ctk.CTkEntry(padre, placeholder_text="Buscar sitio o usuario...")  # campo de búsqueda
        self.entrada_filtro.pack(fill="x", padx=12)  # a lo ancho
        self.entrada_filtro.bind("<KeyRelease>", lambda _evento: self.actualizar_lista())  # al soltar una tecla se vuelve a filtrar la lista

        self.lista_entradas = ctk.CTkScrollableFrame(padre, fg_color=PANEL_ALT)  # área con scroll donde se listan las credenciales
        self.lista_entradas.pack(fill="both", expand=True, padx=10, pady=8)  # ocupa el espacio disponible
        self.etiqueta_info = ctk.CTkLabel(padre, text="Seleccione un registro.", text_color=NEUTRO, justify="left", anchor="w", wraplength=325)  # texto con datos del registro elegido
        self.etiqueta_info.pack(fill="x", padx=13, pady=(0, 8))  # a lo ancho

        # -- Botones para gestionar sitios (en cuadrícula de 2 columnas) -- #
        frame_botones_sitios = ctk.CTkFrame(padre, fg_color="transparent")  # marco de la cuadrícula de botones
        frame_botones_sitios.pack(fill="x", padx=9)  # a lo ancho
        frame_botones_sitios.grid_columnconfigure((0, 1), weight=1)  # las dos columnas se reparten el ancho por igual
        botones = [("Mostrar / ocultar", self.mostrar_no_mostrar_seleccion), ("Copiar contraseña", self.copiar_contraseña_sitio_elegido), ("Historial", self.abrir_historial), ("Eliminar", self.borrar_sitio_elegido)]  # lista de (texto, función) de cada botón
        for indice, (texto, comando) in enumerate(botones):  # enumerate da el número de posición y el par (texto, comando)
            estilo = {"fg_color": "#A63737", "hover_color": "#812727"} if texto == "Eliminar" else BOTON_GUINDA  # el botón Eliminar es rojo; los demás, guinda
            ctk.CTkButton(frame_botones_sitios, text=texto, command=comando, **estilo).grid(row=indice // 2, column=indice % 2, padx=3, pady=3, sticky="ew")  # // da la fila y % la columna: así se forma una cuadrícula de 2 columnas

        ctk.CTkButton(padre, text="Auditar bóveda local", command=self.auditar_boveda, **BOTON_GRIS).pack(fill="x", padx=12, pady=(8, 5))  # botón de auditoría
        ctk.CTkButton(padre, text="Cambiar contraseña maestra", command=self.cambiar_maestra, fg_color="transparent", border_width=1, border_color=GUINDA, text_color=(GUINDA, "#D9A8BE")).pack(fill="x", padx=12, pady=(0, 8))  # botón con solo borde guinda
        ctk.CTkButton(padre, text="Cerrar aplicación", command=self.cerrar_aplicacion, fg_color="transparent", border_width=1, border_color=BORDE, text_color=TEXTO).pack(fill="x", padx=12, pady=(0, 10))  # botón con solo borde gris

        self.actualizar_lista()  # muestra todas las credenciales al abrir, sin pedir una búsqueda


    # AUTENTICACIÓN Y CREACIÓN DE LA BÓVEDA
    # ================================================================
    def alternar_nueva_password(self):  # muestra u oculta los dos campos de la maestra nueva
        mostrar = "" if self.mostrar_nueva.get() else "*"  # "" muestra el texto; "*" lo oculta
        self.entrada_nueva_maestra.configure(show=mostrar)  # aplica al primer campo
        self.entrada_confirmar_maestra.configure(show=mostrar)  # aplica al segundo campo


    def actualizar_fuerza_maestra(self):  # actualiza la barra de fuerza de la maestra nueva
        bits, nivel, color, fraccion = calcular_fuerza(self.var_nueva_maestra.get())  # desempaqueta los 4 valores que devuelve calcular_fuerza
        self.barra_maestra.set(fraccion)  # llena la barra según la fracción (0 a 1)
        self.barra_maestra.configure(progress_color=color if self.var_nueva_maestra.get() else NEUTRO)  # color del nivel, o gris si el campo está vacío
        self.etiqueta_maestra.configure(text=f"{nivel} ({bits:.0f} bits)" if self.var_nueva_maestra.get() else "-")  # texto "Nivel (N bits)"; :.0f redondea a 0 decimales


    def limpiar_campos_login(self):  # vacía el campo de la contraseña maestra del login
        self.login_maestra.delete(0, "end")  # borra desde el carácter 0 hasta el final
        self.login_maestra.focus_set()  # devuelve el cursor al campo


    def iniciar_sesion(self):  # intenta abrir la bóveda con la contraseña escrita
        restante = self.bloqueado_hasta - time.monotonic()  # segundos que faltan para terminar el bloqueo (negativo si ya pasó)
        if restante > 0:  # aún está bloqueado
            self.mensaje_login.configure(text=f"Acceso temporalmente bloqueado. Espere {math.ceil(restante)} segundos.")  # ceil redondea hacia arriba los segundos
            return  # no intenta nada más

        password = self.login_maestra.get()  # lee lo que escribió el usuario
        if not password:  # campo vacío
            self.mensaje_login.configure(text="Escriba la contraseña maestra.")  # pide escribirla
            return  # sale

        self.boton_login.configure(state="disabled", text="Verificando...")  # deshabilita el botón mientras se deriva la llave (scrypt tarda)
        self.update_idletasks()  # fuerza a la interfaz a mostrar ese cambio ya

        try:  # intenta abrir la bóveda
            llave, parametros_kdf, boveda = cargar_boveda(RUTA_BOVEDA, password)  # devuelve la llave, los parámetros de la bóveda (la sal) y los datos
        except ErrorAutenticacion:  # contraseña incorrecta
            self.intentos_fallidos += 1  # suma un intento fallido
            self.limpiar_campos_login()  # vacía el campo
            if self.intentos_fallidos >= MAX_INTENTOS:  # se agotaron los intentos
                self.bloqueado_hasta = time.monotonic() + SEGUNDOS_BLOQUEO  # fija el momento en que termina el bloqueo
                self.intentos_fallidos = 0  # reinicia el contador
                self.mensaje_login.configure(text=f"{MAX_INTENTOS} intentos fallidos. El acceso se bloqueó durante {SEGUNDOS_BLOQUEO} segundos.")  # avisa del bloqueo
            else:  # todavía quedan intentos
                restantes = MAX_INTENTOS - self.intentos_fallidos  # calcula cuántos faltan
                self.mensaje_login.configure(text=f"Contraseña maestra incorrecta. Intentos restantes: {restantes}.")  # los muestra
            self.boton_login.configure(state="normal", text="Desbloquear")  # reactiva el botón
            return  # sale
        except ErrorBoveda as error:  # bóveda dañada o inválida (el orden importa: ErrorAutenticacion va antes porque es una subclase)
            self.limpiar_campos_login()  # vacía el campo
            self.mensaje_login.configure(text=str(error))  # muestra el mensaje del error
            self.boton_login.configure(state="normal", text="Desbloquear")  # reactiva el botón
            return  # sale

        self.intentos_fallidos = 0  # contraseña correcta: reinicia los intentos
        self.bloqueado_hasta = 0  # quita cualquier bloqueo
        self.abrir_sesion(llave, parametros_kdf, boveda)  # entra a la aplicación


    def crear_boveda(self):  # crea la bóveda nueva con la contraseña elegida
        maestra = self.var_nueva_maestra.get()  # lee la contraseña maestra escrita
        error = validar_nueva_maestra(maestra, self.var_confirmar_maestra.get())  # devuelve un mensaje de error o None
        if error:  # si hubo error
            self.mensaje_login.configure(text=error)  # lo muestra
            return  # sale

        if RUTA_BOVEDA.exists():  # revisa de nuevo que no exista ya una bóveda
            self.mensaje_login.configure(text="Ya existe una bóveda. No se sobrescribirá.")  # aviso
            return  # sale

        parametros_kdf = nuevos_parametros_kdf()  # parámetros de la bóveda con una sal nueva
        llave = derivar_llave_fernet(maestra, decodificar_b64(parametros_kdf["salt"]))  # contraseña maestra + sal → llave Fernet
        boveda = nueva_boveda()  # estructura vacía de datos
        try:  # intenta escribir el archivo
            CARPETA_BOVEDAS.mkdir(exist_ok=True)  # crea la carpeta "boveda" si no existe
            with open(RUTA_BOVEDA, "xb") as archivo:  # "x" falla si el archivo ya existe
                archivo.write(cifrar_boveda(boveda, llave, parametros_kdf))  # cifra la bóveda vacía con Fernet y la escribe
        except FileExistsError:  # el archivo apareció justo antes de crearlo
            self.mensaje_login.configure(text="Ya existe una bóveda. No se sobrescribirá.")  # aviso
            return  # sale
        except OSError as error:  # cualquier otro fallo de disco o permisos
            self.mensaje_login.configure(text=f"No se pudo crear la bóveda: {error}")  # muestra el motivo
            return  # sale

        self.abrir_sesion(llave, parametros_kdf, boveda)  # entra directamente a la aplicación
        mostrar_mensaje("Bóveda creada", "La bóveda se creó correctamente. Recuerde su contraseña maestra: no puede recuperarse.", "check")  # confirma la creación


    # CONTROL DE SESIÓN Y SEGURIDAD
    # ================================================================
    def abrir_sesion(self, llave, parametros_kdf, boveda):  # prepara la sesión una vez abierta la bóveda
        boveda.setdefault("settings", {})  # asegura que exista "settings"
        boveda["settings"].setdefault("autolock_min", 5)  # asegura el tiempo de bloqueo (5 min por defecto)
        boveda["settings"].pop("aviso_meses", None)  # elimina un ajuste antiguo; None evita error si no existe
        boveda.setdefault("entries", {})  # asegura que exista "entries"

        # Completa los campos que no tienen las entradas de versiones anteriores
        for entrada in boveda["entries"].values():  # recorre cada credencial guardada
            entrada.setdefault("email", "")  # si falta el correo, pone texto vacío
            entrada.setdefault("created", ahora_iso())  # si falta la fecha de creación, usa la actual
            entrada.setdefault("pwd_changed", entrada["created"])  # si falta la fecha del último cambio, usa la de creación
            entrada.setdefault("history", [])  # si falta el historial, pone lista vacía

        self.llave = llave  # guarda la llave Fernet en la sesión
        self.parametros_kdf, self.boveda = parametros_kdf, boveda  # guarda los parámetros (la sal) y los datos (asignación múltiple)
        self.id_seleccionado = None  # sin credencial elegida
        self.registrar_actividad()  # reinicia el reloj de inactividad
        self.construir_principal()  # muestra la pantalla principal


    def vigilar_inactividad(self):  # se ejecuta cada segundo para bloquear por inactividad
        if self.llave is not None and self.boveda is not None:  # solo si hay una sesión abierta
            limite = int(self.boveda["settings"].get("autolock_min", 5)) * 60  # minutos configurados convertidos a segundos
            if time.monotonic() - self.ultima_actividad > limite:  # ¿pasó más tiempo del permitido sin actividad?
                self.bloquear_boveda(True)  # bloquea indicando que fue por inactividad
        self.after(1000, self.vigilar_inactividad)  # se vuelve a programar a sí misma dentro de 1 segundo


    def bloquear_boveda(self, por_inactividad=False):  # cierra la sesión y vuelve al login
        if self.llave is None:  # ya está bloqueada
            return  # no hace nada
        self.llave = self.boveda = self.parametros_kdf = None  # borra de memoria llave y datos (asignación encadenada)
        self.id_seleccionado = None  # sin selección
        self.construir_login("Bóveda bloqueada por inactividad." if por_inactividad else "Sesión bloqueada.")  # muestra el login con el mensaje correspondiente


    def cerrar_aplicacion(self):  # cierra el programa
        self.llave = self.boveda = self.parametros_kdf = None  # borra datos sensibles de memoria
        self.destroy()  # destruye la ventana y termina mainloop


    # GENERADOR DE CONTRASEÑAS
    # ================================================================
    def generar_password(self):  # se ejecuta al pulsar "Generar"
        try:  # intenta generar
            password_generada = crear_password(self.var_largo.get(), self.var_upper.get(), self.var_digitos.get(), self.var_symbols.get())  # pasa longitud y opciones a la función generadora
        except ValueError as error:  # la longitud no alcanza para los tipos elegidos
            mostrar_mensaje("No se pudo generar", str(error), "warning")  # muestra el motivo
            return  # sale
        self.var_password.set(password_generada)  # coloca la contraseña en el campo
        self.entrada.focus_set()  # deja el cursor en ese campo


    def scale_de_fuerza(self, valor):  # se ejecuta al mover el deslizador de longitud
        self.var_largo.set(round(valor))  # el deslizador da decimales; round los vuelve enteros


    def alternar_mostrar_caracteres(self):  # muestra u oculta la contraseña del campo principal
        self.entrada.configure(show="" if self.var_show.get() else "*")  # "" la muestra; "*" la oculta


    def actualizar_fuerza(self):  # recalcula la barra de fuerza de la contraseña actual
        password = self.var_password.get()  # lee la contraseña del campo
        bits, nivel, color, fraccion = calcular_fuerza(password)  # obtiene los 4 valores de la estimación
        self.barra_progreso.set(fraccion)  # llena la barra
        self.barra_progreso.configure(progress_color=color if password else NEUTRO)  # color del nivel, o gris si no hay texto
        self.etiquetas.configure(text=f"{nivel} ({bits:.0f} bits)" if password else "-")  # actualiza el texto de nivel

        # Avisa si la contraseña ya se usa en otros sitios de la bóveda
        repetida_en = self.sitios_con_password(password, excluir=self.id_seleccionado) if password else []  # lista de sitios que ya usan esa contraseña (vacía si no hay texto)
        if repetida_en:  # si hay coincidencias
            self.etiqueta_estado.configure(text="Contraseña reutilizada en: " + ", ".join(repetida_en), text_color=ADVERTENCIA)  # muestra los sitios separados por coma
        else:  # si no hay
            self.etiqueta_estado.configure(text="")  # borra el aviso


    def limpiar_campos(self):  # vacía el formulario y la selección
        self.var_password.set("")  # vacía la contraseña
        self.var_sitio_web.set("")  # vacía el sitio
        self.var_usuario.set("")  # vacía el usuario
        self.var_correo.set("")  # vacía el correo
        self.id_seleccionado = None  # quita la selección
        self.actualizar_lista()  # redibuja la lista sin selección
        self.etiqueta_info.configure(text="Seleccione un registro.")  # restablece el texto informativo
        self.entrada.focus_set()  # cursor en el campo de contraseña


    def copiar_al_portapapeles(self, password, texto):  # copia un texto al portapapeles y avisa
        self.clipboard_clear()  # vacía el portapapeles
        self.clipboard_append(password)  # agrega el texto
        self.update_idletasks()  # fuerza a que el cambio se aplique
        mostrar_mensaje("Copiado", f"{texto} se copió al portapapeles.", "check")  # confirma al usuario


    def copiar_password(self):  # copia la contraseña del campo principal
        password = self.var_password.get()  # lee la contraseña
        if not password:  # si está vacía
            mostrar_mensaje("Campo vacío", "Genere o escriba una contraseña primero.", "warning")  # avisa
            return  # sale
        self.copiar_al_portapapeles(password, "La contraseña")  # la copia


    # GESTIÓN DE LA BÓVEDA Y CREDENCIALES
    # ================================================================
    def guardar_boveda(self):  # cifra y guarda la bóveda en disco; devuelve True si salió bien
        try:  # intenta guardar
            guardar_en_archivo_boveda(RUTA_BOVEDA, cifrar_boveda(self.boveda, self.llave, self.parametros_kdf))  # primero cifra los datos con Fernet y luego los escribe de forma segura
            return True  # éxito
        except OSError as error:  # fallo de disco o permisos
            mostrar_mensaje("Error al guardar", str(error), "cancel")  # muestra el error
            return False  # fracaso


    def ordenar_entradas(self):  # devuelve las credenciales ordenadas por sitio
        # Ordena los pares (ID, datos) por sitio, sin distinguir mayúsculas y minúsculas.
        return sorted(self.boveda["entries"].items(), key=lambda par: par[1].get("site", "").casefold())  # items() da pares (ID, datos); key indica por qué campo ordenar (par[1] son los datos)


    def sitios_con_password(self, password, excluir=None):  # sitios que usan esa contraseña, sin contar el ID "excluir"
        # Construye un conjunto de sitios que comparten la contraseña, excluyendo la entrada indicada; luego los ordena.
        return sorted({entrada.get("site", "Sin sitio") for id_entrada, entrada in self.boveda["entries"].items() if id_entrada != excluir and entrada.get("password") == password})  # comprensión de conjunto (sin repetidos) con condición; sorted lo vuelve lista ordenada


    def grupos_repetidos(self):  # agrupa las credenciales que comparten contraseña
        grupos = {}  # diccionario: contraseña → lista de IDs
        for id_entrada, entrada in self.boveda["entries"].items():  # recorre cada credencial
            grupos.setdefault(entrada.get("password", ""), []).append(id_entrada)  # crea la lista si no existe y agrega el ID
        # Devuelve solo los grupos con más de una entrada: son los casos de contraseña reutilizada.
        return [ids for ids in grupos.values() if len(ids) > 1]  # lista de grupos con 2 o más IDs


    def actualizar_lista(self):  # redibuja la lista de credenciales
        "Dibuja la lista de sitios (ordenados sin importar mayúsculas) aplicando el filtro de búsqueda"  # docstring de la función
        if self.boveda is None:  # si la bóveda está bloqueada
            return  # no dibuja nada
        for widget in self.lista_entradas.winfo_children():  # recorre los botones que ya estaban
            widget.destroy()  # los elimina para volver a dibujar

        # casefold() normaliza mayúsculas/minúsculas para que la búsqueda no distinga entre ellas.
        consulta = self.entrada_filtro.get().strip().casefold()  # texto de búsqueda sin espacios en los extremos y en minúsculas
        # Aplana los grupos de duplicados en un conjunto de IDs para consultar pertenencia rápidamente.
        ids_repetidos = {id_entrada for grupo in self.grupos_repetidos() for id_entrada in grupo}  # conjunto con todos los IDs que tienen contraseña repetida (doble for en la comprensión)

        if not self.boveda["entries"]:  # si no hay credenciales
            ctk.CTkLabel(self.lista_entradas, text="Todavía no hay credenciales guardadas.", text_color=NEUTRO).pack(pady=24)  # muestra un mensaje
            return  # termina

        for id_entrada, entrada in self.ordenar_entradas():  # recorre las credenciales en orden alfabético
            sitio = entrada.get("site", "Sin sitio")  # nombre del sitio
            cuenta = entrada.get("user", "")  # nombre de usuario
            # Si el texto buscado no aparece en sitio, usuario o correo, no se muestra esta entrada.
            if consulta and consulta not in f"{sitio} {cuenta} {entrada.get('email', '')}".casefold():  # junta sitio, usuario y correo en un texto y busca la consulta ahí
                continue  # salta a la siguiente credencial

            sufijo = "   • REUTILIZADA" if id_entrada in ids_repetidos else ""  # marca visual si la contraseña está repetida
            elegido = id_entrada == self.id_seleccionado  # True si esta es la credencial seleccionada
            # eid=id_entrada guarda el ID de esta iteración; evita que todos los botones apunten al último registro.
            ctk.CTkButton(self.lista_entradas, text=f"{sitio}  |  {cuenta or 'Sin usuario'}{sufijo}", anchor="w", fg_color=(GUINDA, GUINDA_OSCURO) if elegido else "#DEDEDE", hover_color=("#CC7FA5", "#44313A"), text_color="#FFFFFF" if elegido else ("#262126", "#FFFFFF"), command=lambda eid=id_entrada: self.elegir_sitio(eid)).pack(fill="x", padx=4, pady=2)  # botón por credencial: guinda si está elegida, gris si no; al pulsarlo llama a elegir_sitio con su ID


    def elegir_sitio(self, id_entrada):  # se ejecuta al pulsar una credencial de la lista
        "Método para seleccionar un sitio de la lista"  # docstring de la función
        self.id_seleccionado = id_entrada  # recuerda cuál se eligió
        entrada = self.boveda["entries"][id_entrada]  # obtiene sus datos
        self.var_sitio_web.set(entrada.get("site", ""))  # llena el campo sitio
        self.var_usuario.set(entrada.get("user", ""))  # llena el campo usuario
        self.var_correo.set(entrada.get("email", ""))  # llena el campo correo
        self.var_password.set("")  # deja la contraseña vacía (no se muestra por seguridad)
        self.var_show.set(False)  # desmarca "Mostrar"
        self.entrada.configure(show="*")  # vuelve a ocultar el campo
        self.actualizar_lista()  # redibuja para resaltar la selección
        self.actualizar_info_entrada()  # muestra fechas e información del registro


    def actualizar_info_entrada(self):  # actualiza el texto informativo bajo la lista
        if self.id_seleccionado not in self.boveda["entries"]:  # si no hay selección válida
            self.etiqueta_info.configure(text="Seleccione un registro.")  # texto por defecto
            return  # sale
        entrada = self.boveda["entries"][self.id_seleccionado]  # datos de la credencial elegida
        texto = f"Registro creado: {formato_fecha(entrada.get('created'))}\nContraseña actual establecida: {formato_fecha(entrada.get('pwd_changed'))}"  # texto con las dos fechas formateadas, en dos líneas
        duplicados = self.sitios_con_password(entrada.get("password", ""), excluir=self.id_seleccionado)  # otros sitios con la misma contraseña
        if duplicados:  # si hay
            texto += "\nReutilizada también en: " + ", ".join(duplicados)  # agrega una línea con ellos
        if entrada.get("history"):  # si tiene versiones anteriores
            texto += f"\nVersiones anteriores: {len(entrada['history'])}"  # agrega cuántas hay
        self.etiqueta_info.configure(text=texto)  # muestra el texto final


    def salvar_entrada(self):  # guarda o actualiza una credencial (botón "Guardar en bóveda")
        sitio = self.var_sitio_web.get().strip()  # sitio sin espacios sobrantes
        usuario = self.var_usuario.get().strip()  # usuario sin espacios sobrantes
        correo = self.var_correo.get().strip()  # correo sin espacios sobrantes
        password = self.var_password.get()  # contraseña tal cual (los espacios pueden ser parte de ella)

        if not sitio or not usuario:  # faltan campos obligatorios
            mostrar_mensaje("Datos incompletos", "El sitio o servicio y el usuario son obligatorios.", "warning")  # avisa
            return  # sale
        if correo and not REGEX_CORREO.fullmatch(correo):  # si hay correo, debe coincidir completo con el patrón
            mostrar_mensaje("Correo no válido", "Verifique el formato del correo electrónico.", "warning")  # avisa
            return  # sale
        if self.boveda is None:  # si la bóveda se bloqueó mientras tanto
            return  # no guarda nada

        entradas = self.boveda["entries"]  # atajo al diccionario de credenciales

        # Si hay una entrada seleccionada se actualiza esa misma (aunque cambie el usuario o el correo)
        # para conservar su historial. Si no, se busca una igual por sitio + usuario + correo.
        id_existente = self.id_seleccionado if self.id_seleccionado in entradas else None  # usa el ID elegido si existe; si no, None
        if id_existente is None:  # no hay entrada elegida
            # next() devuelve el primer ID que coincide con sitio, usuario y correo; si no hay coincidencia, devuelve None.
            id_existente = next((eid for eid, item in entradas.items() if item.get("site", "").casefold() == sitio.casefold() and item.get("user", "").casefold() == usuario.casefold() and item.get("email", "").casefold() == correo.casefold()), None)  # busca una credencial igual ignorando mayúsculas; None es el valor por defecto de next

        entrada_existente = entradas.get(id_existente) if id_existente else None  # datos de la credencial existente, o None si es nueva
        password_anterior = entrada_existente.get("password", "") if entrada_existente else ""  # contraseña guardada actualmente ("" si es nueva)

        # Al editar una credencial, dejar la contraseña vacía significa conservar la guardada.
        # En una entrada nueva sí es obligatoria.
        if entrada_existente and not password:  # edición sin escribir contraseña nueva
            password_a_guardar = password_anterior  # conserva la anterior
        else:  # entrada nueva o contraseña escrita
            password_a_guardar = password  # usa la escrita

        if not password_a_guardar:  # no hay contraseña
            mostrar_mensaje("Datos incompletos", "Escriba una contraseña para la nueva credencial.", "warning")  # avisa
            return  # sale
        if len(password_a_guardar) < PASSWORD_MIN_LARGO:  # demasiado corta
            mostrar_mensaje("Contraseña demasiado corta", f"Se requieren al menos {PASSWORD_MIN_LARGO} caracteres para guardar esta entrada.", "warning")  # avisa
            return  # sale

        duplicados = self.sitios_con_password(password_a_guardar, excluir=id_existente)  # otros sitios con esa contraseña
        if duplicados and not confirmar("Contraseña reutilizada", "La contraseña ya se utiliza en: " + ", ".join(duplicados) + "\n\nSi una de esas cuentas se ve comprometida, las demás podrían quedar expuestas. ¿Desea continuar?"):  # si hay duplicados, pregunta; si el usuario dice No, confirmar devuelve False y se cancela
            return  # sale

        password_cambio = bool(entrada_existente and password_anterior != password_a_guardar)  # True si es una edición y la contraseña es distinta
        if password_cambio and not confirmar("Actualizar credencial", "La entrada ya existe. ¿Desea reemplazar la contraseña? La versión anterior se conservará en el historial."):  # pide confirmación para reemplazarla
            return  # sale si dijo No

        marca_tiempo = ahora_iso()  # fecha y hora de esta operación
        if entrada_existente:  # caso: actualizar
            entrada = entrada_existente  # alias para escribir más corto
            if password_cambio:  # si cambió la contraseña
                historial = entrada.setdefault("history", [])  # obtiene la lista del historial (la crea si no existe)
                # Inserta la contraseña anterior al principio para mantener primero la versión más reciente.
                historial.insert(0, {"password": password_anterior, "replaced": marca_tiempo})  # inserta en la posición 0 la contraseña vieja y cuándo se reemplazó
                # Elimina las versiones que excedan el máximo de elementos permitido.
                del historial[LIMITE_HISTORIAL:]  # solo se conservan las últimas versiones
                entrada["password"] = password_a_guardar  # guarda la contraseña nueva
                entrada["pwd_changed"] = marca_tiempo  # actualiza la fecha del cambio
            entrada.update({"site": sitio, "user": usuario, "email": correo})  # actualiza sitio, usuario y correo
            self.id_seleccionado = id_existente  # deja seleccionada esta credencial
            mensaje_exito = "La contraseña se reemplazó y la versión anterior quedó guardada en el historial." if password_cambio else "Los datos se actualizaron. La contraseña existente se conservó sin cambios."  # elige el mensaje según si cambió la contraseña
        else:  # caso: credencial nueva
            # Genera un identificador aleatorio único para distinguir esta credencial.
            self.id_seleccionado = uuid.uuid4().hex  # ID aleatorio en hexadecimal
            entradas[self.id_seleccionado] = {"site": sitio, "user": usuario, "email": correo, "password": password_a_guardar, "created": marca_tiempo, "pwd_changed": marca_tiempo, "history": []}  # crea la credencial con todos sus campos
            mensaje_exito = "La nueva credencial se guardó en la bóveda local."  # mensaje para el caso nuevo

        if self.guardar_boveda():  # intenta escribir en disco
            self.actualizar_lista()  # redibuja la lista
            self.actualizar_info_entrada()  # actualiza el texto informativo
            mostrar_mensaje("Guardado", mensaje_exito, "check")  # confirma al usuario


    def entrada_elegida(self):  # devuelve los datos de la credencial seleccionada, o None
        if self.id_seleccionado not in self.boveda["entries"]:  # no hay una selección válida
            mostrar_mensaje("Sin selección", "Seleccione un registro de la bóveda.", "warning")  # avisa
            return None  # devuelve None
        return self.boveda["entries"][self.id_seleccionado]  # devuelve el diccionario de la credencial


    def mostrar_no_mostrar_seleccion(self):  # alterna entre mostrar y ocultar la contraseña elegida
        "Método para ocultar o mostrar la contraseña del sitio elegido"  # docstring de la función
        entrada = self.entrada_elegida()  # obtiene la credencial seleccionada
        if entrada is None:  # si no hay
            return  # sale
        if self.var_password.get() == entrada["password"]:  # si ya se está mostrando
            self.var_password.set("")  # la quita del campo
            self.var_show.set(False)  # desmarca "Mostrar"
        else:  # si no se está mostrando
            self.var_password.set(entrada["password"])  # la coloca en el campo
            self.var_show.set(True)  # marca "Mostrar"
        self.alternar_mostrar_caracteres()  # aplica el estado visible u oculto al campo


    def copiar_contraseña_sitio_elegido(self):  # copia la contraseña de la credencial elegida
        entrada = self.entrada_elegida()  # obtiene la credencial
        if entrada:  # si existe
            self.copiar_al_portapapeles(entrada["password"], f"La contraseña de {entrada['site']}")  # copia y avisa con el nombre del sitio


    def borrar_sitio_elegido(self):  # elimina la credencial elegida
        entrada = self.entrada_elegida()  # obtiene la credencial
        if entrada is None:  # si no hay
            return  
        if not confirmar("Eliminar credencial", f"¿Desea eliminar la entrada de {entrada.get('site')} y todo su historial?"):  # pide confirmación
            return  # sale si dijo No
        self.boveda["entries"].pop(self.id_seleccionado, None)  # la quita del diccionario (None evita error si no existe)
        self.id_seleccionado = None  # quita la selección
        if self.guardar_boveda():  # guarda los cambios en disco
            self.limpiar_campos()  # limpia el formulario y redibuja


    # AUDITORÍA E HISTORIAL
    # ================================================================
    def auditar_boveda(self):  # genera un reporte de contraseñas repetidas y débiles
        entradas = self.boveda["entries"]  # atajo al diccionario de credenciales
        if not entradas:  # bóveda vacía
            mostrar_mensaje("Bóveda vacía", "No hay credenciales que auditar.", "info")  # avisa
            return  

        def etiqueta_de(id_entrada):  # función interna: texto legible de una credencial
            entrada = entradas[id_entrada]  # datos de esa credencial
            cuenta = entrada.get("user") or entrada.get("email") or "sin cuenta"  # usa el usuario; si no hay, el correo; si no, "sin cuenta"
            return f"{entrada.get('site', 'Sin sitio')} ({cuenta})"  # formato "Sitio (cuenta)"

        lineas = ["AUDITORÍA LOCAL DE LA BÓVEDA", "La revisión utiliza exclusivamente las credenciales almacenadas en esta bóveda.", "", "1. CONTRASEÑAS REUTILIZADAS"]  # lista con las primeras líneas del reporte; "" es una línea en blanco
        repetidas = self.grupos_repetidos()  # grupos de IDs con la misma contraseña
        if repetidas:  # si hay
            for grupo in repetidas:  # recorre cada grupo
                lineas.append("• " + ", ".join(etiqueta_de(eid) for eid in grupo))  # agrega una línea con las credenciales del grupo
        else:  # si no hay
            lineas.append("No se detectaron contraseñas repetidas.")  # mensaje de que todo está bien

        lineas.extend(["", "2. CONTRASEÑAS DÉBILES (estimación local)"])  # agrega la línea en blanco y el encabezado de la sección 2
        debiles = []  # lista donde se guardan las líneas de contraseñas débiles
        for id_entrada, entrada in self.ordenar_entradas():  # recorre en orden alfabético
            bits, nivel, _, _ = calcular_fuerza(entrada.get("password", ""))  # solo interesan bits y nivel; los "_" descartan color y fracción
            if bits < 40:  # menos de 40 bits se considera débil
                debiles.append(f"• {etiqueta_de(id_entrada)}: {nivel} (estimación de {bits:.0f} bits)")  # agrega la línea descriptiva
        # Si debiles está vacío, agrega el mensaje alternativo; de lo contrario, incorpora los resultados.
        lineas.extend(debiles or ["No se detectaron contraseñas débiles según el estimador local."])  # una lista vacía cuenta como False, así que "or" usa el mensaje alternativo

        lineas.extend(["", "ALCANCE Y LIMITACIÓN", "Esta auditoría no consulta servicios externos ni bases de datos de filtraciones.", "Por tanto, no puede determinar si una contraseña aparece en incidentes o filtraciones conocidas.", "La estimación de fuerza es orientativa y no sustituye un análisis especializado."])  # agrega el aviso de alcance y limitaciones

        ventana = ctk.CTkToplevel(self)  # ventana secundaria que depende de la principal
        ventana.title("Auditoría local de la bóveda")  # título de la ventana
        ventana.geometry("720x570")  # tamaño de la ventana
        ventana.transient(self)  # la mantiene encima de la principal
        ventana.after(100, ventana.lift)  # tras 100 ms la trae al frente (CTkToplevel a veces aparece detrás)
        ctk.CTkLabel(ventana, text="Resultados de auditoría", font=ctk.CTkFont(size=19, weight="bold")).pack(anchor="w", padx=16, pady=(14, 5))  # título
        cuadro_texto = ctk.CTkTextbox(ventana, wrap="word")  # cuadro de texto grande; wrap="word" no corta palabras al saltar de línea
        cuadro_texto.pack(fill="both", expand=True, padx=14, pady=12)  # ocupa la ventana
        cuadro_texto.insert("1.0", "\n".join(lineas))  # inserta desde la línea 1, carácter 0, todas las líneas unidas con saltos
        cuadro_texto.configure(state="disabled")  # lo vuelve de solo lectura


    def abrir_historial(self):  # abre la ventana con contraseñas anteriores
        entrada = self.entrada_elegida()  # obtiene la credencial elegida
        if entrada is None:  # si no hay
            return  # sale
        ventana = ctk.CTkToplevel(self)  # ventana secundaria
        ventana.title(f"Historial - {entrada.get('site', '')}")  # título con el nombre del sitio
        ventana.geometry("620x440")  # tamaño inicial
        ventana.minsize(480, 300)  # tamaño mínimo
        ventana.transient(self)  # se mantiene encima de la principal
        ventana.after(100, ventana.lift)  # la trae al frente

        ctk.CTkLabel(ventana, text=f"{entrada.get('site')} - {entrada.get('user') or 'Sin usuario'}", font=ctk.CTkFont(size=17, weight="bold")).pack(anchor="w", padx=15, pady=(14, 4))  # encabezado con sitio y usuario
        ctk.CTkLabel(ventana, text=f"Se conservan hasta {LIMITE_HISTORIAL} versiones anteriores.", text_color=NEUTRO).pack(anchor="w", padx=15)  # nota del límite
        area = ctk.CTkScrollableFrame(ventana, orientation="vertical")  # área con scroll vertical
        area.pack(fill="both", expand=True, padx=12, pady=12)  # ocupa el espacio

        historial = entrada.get("history", [])  # lista de versiones anteriores
        if not historial:  # si no hay
            ctk.CTkLabel(area, text="No hay versiones anteriores.", text_color=NEUTRO).pack(pady=25)  # mensaje
            return  # sale

        for version in historial[:LIMITE_HISTORIAL]:  # recorre como máximo las 10 versiones más recientes (slicing)
            fila = ctk.CTkFrame(area, fg_color=PANEL, corner_radius=8)  # tarjeta de la versión
            fila.pack(fill="x", pady=4)  # a lo ancho
            fila.grid_columnconfigure(1, weight=1)  # la columna 1 (contraseña) absorbe el espacio sobrante
            ctk.CTkLabel(fila, text=formato_fecha(version.get("replaced")), width=125, anchor="w").grid(row=0, column=0, padx=8, pady=7, sticky="w")  # fecha en que se reemplazó
            enmascarada = ctk.CTkLabel(fila, text="•" * 14, font=("Consolas", 13), anchor="w")  # muestra 14 puntos que ocultan la contraseña
            enmascarada.grid(row=0, column=1, padx=5, pady=7, sticky="ew")  # la ubica en la columna 1
            estado = {"visible": False}  # diccionario que recuerda si esta fila está visible (se usa un diccionario porque se puede modificar desde la función interna)

            # Los valores por defecto fijan los datos de esta fila para que cada botón actúe sobre su propia versión.
            def alternar(item=version, etiqueta=enmascarada, estado=estado):  # función interna; los argumentos con valor por defecto "congelan" los de esta vuelta del bucle
                estado["visible"] = not estado["visible"]  # invierte entre visible y oculto
                etiqueta.configure(text=item.get("password", "") if estado["visible"] else "•" * 14)  # muestra la contraseña o los puntos

            ctk.CTkButton(fila, text="Mostrar", width=72, command=alternar, **BOTON_GUINDA).grid(row=0, column=2, padx=3, pady=5)  # botón que ejecuta alternar
            ctk.CTkButton(fila, text="Copiar", width=68, command=lambda pwd=version.get("password", ""): self.copiar_al_portapapeles(pwd, "La contraseña anterior"), **BOTON_GUINDA).grid(row=0, column=3, padx=(2, 8), pady=5)  # botón que copia la contraseña de esta versión (pwd=... fija el valor de esta vuelta)


    # CONFIGURACIÓN DE SEGURIDAD
    # ================================================================
    def cambiar_autobloqueo(self, seleccion):  # se ejecuta al elegir un tiempo en el menú de bloqueo automático
        self.boveda["settings"]["autolock_min"] = self.opciones_bloqueo[seleccion]  # traduce el texto elegido a minutos y lo guarda en los ajustes
        self.guardar_boveda()  # escribe el cambio en disco


    def cambiar_maestra(self):  # abre la ventana para cambiar la contraseña maestra
        ventana = ctk.CTkToplevel(self)  # ventana secundaria
        ventana.title("Cambiar contraseña maestra")  # título
        ventana.geometry("480x590")  # tamaño
        ventana.transient(self)  # se mantiene encima de la principal
        ventana.after(100, ventana.lift)  # la trae al frente

        entrada_actual = ctk.CTkEntry(ventana, show="*", placeholder_text="Contraseña maestra actual")  # campo de la contraseña actual (se crea aquí y se coloca después)
        var_nueva = ctk.StringVar()  # variable de la contraseña nueva
        var_confirmar = ctk.StringVar()  # variable de la confirmación

        ctk.CTkLabel(ventana, text="Cambiar contraseña maestra", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(18, 12))  # título
        ctk.CTkLabel(ventana, text="Contraseña actual").pack(anchor="w", padx=22)  # etiqueta del primer campo
        entrada_actual.pack(fill="x", padx=22, pady=(4, 12))  # coloca el campo de la contraseña actual
        ctk.CTkLabel(ventana, text=f"Nueva contraseña (mínimo {MASTER_MIN_LARGO} caracteres)").pack(anchor="w", padx=22)  # etiqueta del segundo campo
        entrada_nueva = ctk.CTkEntry(ventana, show="*", textvariable=var_nueva)  # campo de la contraseña nueva
        entrada_nueva.pack(fill="x", padx=22, pady=(4, 12))  # lo coloca
        ctk.CTkLabel(ventana, text="Confirmar nueva contraseña").pack(anchor="w", padx=22)  # etiqueta del tercer campo
        entrada_confirmar = ctk.CTkEntry(ventana, show="*", textvariable=var_confirmar)  # campo de confirmación
        entrada_confirmar.pack(fill="x", padx=22, pady=(4, 12))  # lo coloca

        var_mostrar = ctk.BooleanVar(value=False)  # variable de la casilla "mostrar"

        def alternar_campos():  # función interna: muestra u oculta los tres campos
            valor = "" if var_mostrar.get() else "*"  # "" muestra; "*" oculta
            for widget in (entrada_actual, entrada_nueva, entrada_confirmar):  # recorre los tres campos
                widget.configure(show=valor)  # aplica el valor a cada uno

        ctk.CTkCheckBox(ventana, text="Mostrar contraseñas", variable=var_mostrar, command=alternar_campos).pack(anchor="w", padx=22, pady=5)  # casilla que llama a alternar_campos
        mensaje = ctk.CTkLabel(ventana, text="", text_color=ADVERTENCIA, wraplength=420, justify="left")  # etiqueta para mensajes de error
        mensaje.pack(fill="x", padx=22, pady=10)  # la coloca

        def aplicar_cambio():  # función interna: se ejecuta al pulsar el botón de actualizar
            if self.llave is None:  # si la bóveda se bloqueó mientras tanto
                return  # no hace nada
            actual = entrada_actual.get()  # contraseña actual escrita
            nueva = var_nueva.get()  # contraseña nueva escrita
            error = validar_nueva_maestra(nueva, var_confirmar.get())  # valida coincidencia y fuerza
            if error:  # si hay error
                mensaje.configure(text=error)  # lo muestra
                return  # sale
            if nueva == actual:  # la nueva no puede ser igual a la actual
                mensaje.configure(text="La nueva contraseña debe ser distinta de la actual.")  # avisa
                return  # sale

            # Se deriva la llave con la contraseña escrita y se compara con la llave de la sesión
            llave_vieja = derivar_llave_fernet(actual, decodificar_b64(self.parametros_kdf["salt"]))  # deriva la llave con lo que escribió el usuario y la sal guardada
            # Compara las llaves con una función diseñada para evitar filtraciones por diferencias de tiempo.
            if not secrets.compare_digest(llave_vieja, self.llave):  # si no coincide con la llave de la sesión, la contraseña actual es incorrecta
                mensaje.configure(text="La contraseña maestra actual es incorrecta.")  # avisa
                return  # sale

            # Crea una sal nueva; por tanto, la nueva contraseña maestra producirá una llave diferente.
            parametros_nuevos = nuevos_parametros_kdf()  # parámetros nuevos (sal nueva)
            llave_nueva = derivar_llave_fernet(nueva, decodificar_b64(parametros_nuevos["salt"]))  # llave Fernet derivada de la contraseña nueva
            try:  # intenta guardar
                # Vuelve a cifrar toda la bóveda con la nueva llave antes de guardar el archivo actualizado.
                guardar_en_archivo_boveda(RUTA_BOVEDA, cifrar_boveda(self.boveda, llave_nueva, parametros_nuevos))  # re-cifra todo con la llave nueva y reemplaza el archivo
            except OSError as error:  # fallo de disco
                mensaje.configure(text=f"No se pudo guardar la bóveda: {error}")  # muestra el motivo
                return  # sale, conservando la llave anterior

            self.llave, self.parametros_kdf = llave_nueva, parametros_nuevos  # actualiza la sesión con la llave y los parámetros nuevos
            ventana.destroy()  # cierra la ventana
            mostrar_mensaje("Contraseña actualizada", "La contraseña maestra se cambió correctamente.", "check")  # confirma el cambio

        ctk.CTkButton(ventana, text="Actualizar contraseña maestra", command=aplicar_cambio, **BOTON_GUINDA).pack(fill="x", padx=22, pady=12)  # botón que ejecuta aplicar_cambio

# --- Programa principal --- #
if __name__ == "__main__":  # solo se ejecuta si corres este archivo directamente (no si lo importas)
    app = Aplicacion()  # crea la ventana de la aplicación
    app.mainloop()  # inicia el bucle de eventos: mantiene la ventana abierta
