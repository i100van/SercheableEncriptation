#!/usr/bin/python
import struct
import os
import base64
import sys
from Crypto.Cipher import AES
from Crypto.Cipher import ARC2
import time


N_ARBITRARIO =        '98765432'
CLAVE_ENCRIPTADO =    '1234567891234567'
CLAVE_CIFRADO_FLUJO = '9876543219876543'#16 caracteres 128bits

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def separacion_chunk(chunk, longitud):
    return (chunk[0 + i:longitud + i] for i in range(0, len(chunk), longitud))

texto_aleatorio = 'opasdfgh'

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


class CifradorRC2:
    def __init__(self, clave):
        self.clave = clave

    def cifrar(self, datos):
        iv = texto_aleatorio
        cifrador =  ARC2.new(self.clave, ARC2.MODE_CFB, iv)# https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
        return cifrador.encrypt(datos)

    def descifrar(self, encriptado):
        code = base64.b64decode(encriptado)
        iv = code[:8]
        cifrador =  ARC2.new(self.clave, ARC2.MODE_CFB, iv)
        return unpad(cifrador.decrypt(encriptado[8:]))


def encriptarfichero_RC2():
    cifrado_de_fujo = Cifrado_de_fujo(CLAVE_CIFRADO_FLUJO)
    w_bf_cifrador = CifradorRC2(CLAVE_ENCRIPTADO)
    s_bf_cifrador = CifradorRC2(CLAVE_ENCRIPTADO)
    for nombre_fichero in os.listdir("./datos/"):
        print('Tiempo invertido en:',nombre_fichero)
        with open(os.path.join('./datos/', nombre_fichero), 'rb') as fichero_entrada:
            with open(os.path.join('./salida/RC2', nombre_fichero + '.enc'), 'wb') as salida:
                for linea in fichero_entrada:
                    for palabra in linea.split():
                        palabra_cifrar = palabra.ljust(32, bytes('.', 'utf-8'))
                        EWi = w_bf_cifrador.cifrar(palabra_cifrar)
                        Si = cifrado_de_fujo.generar()
                        FiSi = s_bf_cifrador.cifrar(Si)
                        Ti = Si + FiSi
                        ciphertext = byte_xor(EWi, Ti)
                        salida.write(ciphertext)
    salida.close()

def buscar_RC2(palabra):
        try:
            w_bf_cipher = CifradorRC2(CLAVE_ENCRIPTADO)
            s_bf_cipher = CifradorRC2(CLAVE_ENCRIPTADO)
            palabra_justificada = palabra.ljust(32, '.') 
            cifradoBuscar = w_bf_cipher.cifrar(palabra_justificada)
            for fichero in os.listdir('./salida/RC2'):
                encontrada = 0
                with open(os.path.join('./salida/RC2', fichero), 'rb') as entrada:
                   dato = entrada.read(32)
                   while dato:
                        Ti = byte_xor(cifradoBuscar, dato)
                        Ti = list(separacion_chunk(Ti, 8))
                        if s_bf_cipher.cifrar(Ti[0]) == Ti[1]:
                            encontrada = 1;
                            break
                        dato = entrada.read(32)
                if (encontrada==1):
                     print ('Encontrado en el fichero {0}'.format(fichero))
                else :
                    print('No encontrado en {0}'.format(fichero))
        except EOFError:
            print ('\nError\n')
            sys.exit(0)
            
inicio=time.time()            
encriptarfichero_RC2()
fin=time.time()
print('Tiempo ivertido en encriptar',fin-inicio)
buscar_RC2("nombre1")
buscar_RC2("nombre40")