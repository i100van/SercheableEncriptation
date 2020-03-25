#!/usr/bin/python
import struct
import os
import base64
import sys
from matplotlib import pyplot
import traceback
from Crypto.Cipher import AES
from Crypto.Util import Counter
import time

N_ARBITRARIO =        '98765432'
CLAVE_ENCRIPTADO =    '1234567891234567'
CLAVE_CIFRADO_FLUJO = '9876543219876543'#16 caracteres 128bits

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def separacion_chunk(chunk, longitud):
    return (chunk[0 + i:longitud + i] for i in range(0, len(chunk), longitud))

texto_aleatorio = 'qwertyuiopasdfgh'

class Contador:
    def __init__(self, n_arbitrario):
        assert(len(n_arbitrario)==8)
        self.n_arbitrario = n_arbitrario
        self.cnt = 0

    def __call__(self):
        derecha = struct.pack('>Q',self.cnt)
        self.cnt += 1
        return self.n_arbitrario.encode() + derecha

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
    
class Cifrado_de_fujo:
    def __init__(self, clave):
        self.clave_flujo = clave

    def generar(self):
        cifrado_de_fujo = AES.new(self.clave_flujo, AES.MODE_CTR, counter=Contador(N_ARBITRARIO))  # https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ctr-mode
        return cifrado_de_fujo.encrypt(texto_aleatorio)

    def descifrar(self, encriptado):
        cifrado_de_fujo = AES.new(self.clave_flujo, AES.MODE_CTR, counter=Contador(N_ARBITRARIO))
        return cifrado_de_fujo.decrypt(encriptado)


class CifradorAES:
    def __init__(self, clave):
        self.claveAES = clave

    def cifrar(self, datos):
        iv = texto_aleatorio
        cifrador = AES.new(self.claveAES,AES.MODE_CBC,iv) # https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
        return cifrador.encrypt(datos)

    def descifrar(self, encriptado):
        code = base64.b64decode(encriptado)
        iv = code[:16]
        cifrador = AES.new(self.claveAES, AES.MODE_CBC, iv)
        return unpad(cifrador.decrypt(encriptado[16:]))
    
def mostrar_datos(datos):
    print(datos)
    longitud_fichero=[]
    tiempos=[]
    for i in range(len(datos[0])):
        longitud_fichero.append(datos[0][i])
        tiempos.append(datos[1][i])
    pyplot.plot(longitud_fichero,tiempos,'bo')

def encriptarfichero():
    tiempos=[]
    longitud_fichero=[]
    cifrado_de_fujo = Cifrado_de_fujo(CLAVE_CIFRADO_FLUJO)
    w_aes_cifrador = CifradorAES(CLAVE_ENCRIPTADO)
    s_aes_cifrador = CifradorAES(CLAVE_ENCRIPTADO)
    for nombre_fichero in os.listdir("./datos/"):
        inicio=time.time()
        with open(os.path.join('./datos/', nombre_fichero), 'rb') as fichero_entrada:
            with open(os.path.join('./salida/', nombre_fichero + '.enc'), 'wb') as salida:
                for linea in fichero_entrada:
                    for palabra in linea.split():
                        palabra_cifrar = palabra.ljust(32, bytes('.', 'utf-8'))
                        EWi = w_aes_cifrador.cifrar(palabra_cifrar)
                        Si = cifrado_de_fujo.generar()
                        FiSi = s_aes_cifrador.cifrar(Si)
                        Ti = Si + FiSi
                        ciphertext = byte_xor(EWi, Ti)
                        salida.write(ciphertext)
                longitud_fichero.append(os.stat(os.path.join('./datos/', nombre_fichero)).st_size)
        fin=time.time()
        tiempos.append(fin-inicio)
        datos=[]
        datos.append(longitud_fichero)
        datos.append(tiempos)
    return datos
    salida.close()

def buscar(palabra):
    try:
        ficheros_encontrada=[]
        w_aes_cipher = CifradorAES(CLAVE_ENCRIPTADO)
        s_aes_cipher = CifradorAES(CLAVE_ENCRIPTADO)
        palabra_justificada = palabra.ljust(32, '.') 
        cifradoBuscar = w_aes_cipher.cifrar(palabra_justificada)
        for fichero in os.listdir('./salida/'):
            encontrada = 0
            with open(os.path.join('./salida/', fichero), 'rb') as entrada:
               dato = entrada.read(32)
               while dato:
                    Ti = byte_xor(cifradoBuscar, dato)
                    Ti = list(separacion_chunk(Ti, 16))
                    if s_aes_cipher.cifrar(Ti[0]) == Ti[1]:
                        encontrada = 1;
                        break
                    dato = entrada.read(32)
            if (encontrada==1):
                ficheros_encontrada.append(fichero)
        return ficheros_encontrada
    except EOFError:
        print ('\nError\n')
        sys.exit(0)

            
inicio=time.time()            
datos=encriptarfichero()
print("datos")
mostrar_datos(datos)
fin=time.time()
print('Tiempo total invertido en encriptar',fin-inicio)
palabra = ""

while not(palabra=="salir"):
    palabra = input('\nPalabra a buscar: ')
    if not palabra:
            print('Introduzca un texto')
            continue
    resultado=buscar(palabra)
    if(len(resultado)==0):
        print("No encontrado")
    else:
        print(resultado)