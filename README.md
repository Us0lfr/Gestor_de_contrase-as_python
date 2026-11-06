# Gestor_de_contraseñas_python
> Proyecto realizado por **Del Castillo Camacho Osvaldo Ulrick y Téllez Hernández Daniel, Alumnos de la MISTI CULHUACAN.**

El propósito de esta herramienta es ofrecer un gestor de contraseñas local que sugiera claves robustas, eliminando la necesidad de registros obligatorios y evitando que terceros no deseados recolecten información del usuario.

---

##  Tecnologías utilizadas :robot:

| Tecnología | Uso |
|---|---|
| [python](https://www.python.org/) | Lenguaje de programación |
| [Customtkinter](https://customtkinter.tomschimansky.com/) | Librería de Interfaz Gráfica basada en Tkinter |
| [VisualStudioCode](https://code.visualstudio.com/) | Entorno de Desarrollo Integrado (IDE) |


---

## Instalación y ejecución :beginner:
> La herramienta está diseñada para correr en sistemas operativos como: Windows, Linux y MacOS.

### 1. Instalación.
Instalar python: :snake:
> Python tiene por defecto la herramienta de Tkinter, por lo que sólo requerimos después instalar el módulo de Customtkinter.
**Windows**

```bash
winget install Python.Python.3.12
```
**Linux**

Dependiendo la distribución buscar el gestor de paquetes adecuado.

```bash
sudo apt update
sudo apt install python3 python3-pip
```
**MacOS**
```bash
brew install python
```
### 2. Instalar los módulos necesarios.
**Windows**
```bash
pip install customtkinter CTkMessagebox
```

**Linux y MacOs**
```bash
pip3 install customtkinter CTkMessagebox
```

### 3. Descargar la Herramienta de este repositorio.
> Desde la terminal ( no importa el sistema operativo), copiar y ejecutar el siguiente comando.
```bash
curl -o Gestor-contraseñas.py https://github.com/Us0lfr/Gestor_de_contrase-as_python/blob/main/Gestor_contrasenas.py
```

### 4. Ejecutar. :rocket:

**Windows**

Abre la terminal (CMD o PowerShell) en la carpeta donde descargaste el archivo y ejecuta:
```bash
python Gestor-contraseñas.py
```

**Linux y macOS**
Abre tu terminal, navega a la carpeta del archivo y ejecuta:

```bash
chmod +x tu_script.py
```
(Esto establece permisos de ejecución del archivo).

```bash
python3 Gestor-contraseñas.py
```

---
## Notas :notebook:

---
## Disclosure :warning:
1. Almacenamiento y Privacidad:

**Esta herramienta opera de manera 100% local.** Todas las credenciales se cifran directamente en el dispositivo del usuario. La aplicación no recopila, transmite ni comparte información personal, métricas de uso ni contraseñas con servidores externos o terceros.

2. Responsabilidad de la Contraseña Maestra:

Debido a la arquitectura de cifrado utilizada, el desarrollador no tiene acceso a sus datos ni posee mecanismos para restablecer la contraseña maestra. Si olvida su clave maestra, el acceso a los datos almacenados se perderá de forma permanente.

3. Exención de Garantías y Limitación de Responsabilidad:

Este software se proporciona "tal cual" (AS IS), sin garantías de ningún tipo. *El usuario asume toda la responsabilidad sobre la custodia de sus datos y la seguridad del dispositivo donde se ejecute la herramienta. En ningún caso el autor será responsable por la pérdida de información o daños derivados del uso de este programa.*

