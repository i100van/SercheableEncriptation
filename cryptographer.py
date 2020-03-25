#!/usr/bin/python
import struct
import os
import base64
import sys
from matplotlib import pyplot
from Crypto.Cipher import ARC2
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
import matplotlib.patches as mpatches
import time

############ ELEMENTOS EN COMUN PARA CIFRADO ##################
N_ARBITRARIO =        '98765432'
CLAVE_ENCRIPTADO =    '1234567891234567'
CLAVE_CIFRADO_FLUJO = '1234567891234567'#16 caracteres 128bits

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

texto_aleatorio_16 = 'qwertyuiopasdfgh'
texto_aleatorio_8 = 'opasdfgh'

def mostrar_datos(datosA,datosB,datosC):
    longitud_fichero=[]
    tiempos_AES=[]
    tiempos_BlowFish=[]
    tiempos_RC2=[]
    for i in range(len(datosA[0])):
        longitud_fichero.append(datosA[0][i])
        tiempos_AES.append(datosA[1][i])
        tiempos_BlowFish.append(datosB[1][i])
        tiempos_RC2.append(datosC[1][i])
    pyplot.plot(longitud_fichero,tiempos_AES,'bo')
    pyplot.plot(longitud_fichero,tiempos_BlowFish,'ro')
    pyplot.plot(longitud_fichero,tiempos_RC2,'go')
    green_patch = mpatches.Patch(color='green', label='BlowFish')
    red_patch = mpatches.Patch(color='red', label='RC2')
    blue_patch = mpatches.Patch(color='blue', label='AES')
    pyplot.legend(handles=[red_patch,green_patch,blue_patch])
    pyplot.show()

def separacion_chunk(chunk, longitud):
    return (chunk[0 + i:longitud + i] for i in range(0, len(chunk), longitud))


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
        return cifrado_de_fujo.encrypt(texto_aleatorio_16)

    def descifrar(self, encriptado):
        cifrado_de_fujo = AES.new(self.clave_flujo, AES.MODE_CTR, counter=Contador(N_ARBITRARIO))
        return cifrado_de_fujo.decrypt(encriptado)


def buscar_ficheros(cifradoBuscar, ruta, s_aes_cipher):
    tiempos=[]
    longitud_ficheros=[]
    ficheros_encontrada=[]
    datos = []
    for fichero in os.listdir(ruta):
        inicio = time.time()
        encontrada = 0
        with open(os.path.join(ruta, fichero), 'rb') as entrada:
            dato = entrada.read(32)
            while dato:
                Ti = byte_xor(cifradoBuscar, dato)
                Ti = list(separacion_chunk(Ti, 16))
                if s_aes_cipher.cifrar(Ti[0]) == Ti[1]:
                    encontrada = 1;
                    fin = time.time()
                    break
                dato = entrada.read(32)
        if (encontrada == 1):
            tiempos.append(fin - inicio)
            longitud_ficheros.append(os.stat(os.path.join(ruta, fichero)).st_size)
            #ficheros_encontrada.append(fichero)
    datos.append(longitud_ficheros)
    datos.append(tiempos)
    #datos.append(ficheros_encontrada)
    return datos

def encriptar_fichero(cifrado_de_fujo_b, ruta, s_bf_cifrador, w_bf_cifrador):
    tiempos=[]
    longitud_ficheros=[]
    for nombre_fichero in os.listdir("./datos/"):
        inicio = time.time()
        with open(os.path.join('./datos/', nombre_fichero), 'rb') as fichero_entrada:
            with open(os.path.join(ruta, nombre_fichero + '.enc'), 'wb') as salida:
                for linea in fichero_entrada:
                    for palabra in linea.split():
                        palabra_cifrar = palabra.ljust(32, bytes('.', 'utf-8'))
                        EWi = w_bf_cifrador.cifrar(palabra_cifrar)
                        Si = cifrado_de_fujo_b.generar()
                        FiSi = s_bf_cifrador.cifrar(Si)
                        Ti = Si + FiSi
                        ciphertext = byte_xor(EWi, Ti)
                        salida.write(ciphertext)
        fin = time.time()
        tiempos.append(fin - inicio)
        longitud_ficheros.append(os.stat(os.path.join('./datos/', nombre_fichero)).st_size)
    datos = []
    datos.append(longitud_ficheros)
    datos.append(tiempos)
    salida.close()
    return datos

############ CIFRADO MEDIANTE BlowFish ################## 
        
class CifradorBlowFish:
    def __init__(self, clave):
        self.clave = clave

    def cifrar(self, datos):
        iv = texto_aleatorio_8
        cifrador =  Blowfish.new(self.clave, Blowfish.MODE_CBC, iv)# https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
        return cifrador.encrypt(datos)

    def descifrar(self, encriptado):
        code = base64.b64decode(encriptado)
        iv = code[:8]
        cifrador =  Blowfish.new(self.clave, Blowfish.MODE_CBC, iv)
        return unpad(cifrador.decrypt(encriptado[8:]))


def encriptarficheroBlowFish():
    cifrado_de_fujo_b = Cifrado_de_fujo(CLAVE_CIFRADO_FLUJO)
    w_bf_cifrador = CifradorBlowFish(CLAVE_ENCRIPTADO)
    s_bf_cifrador = CifradorBlowFish(CLAVE_ENCRIPTADO)
    ruta='./salida/BlowFish'
    return encriptar_fichero(cifrado_de_fujo_b, ruta, s_bf_cifrador, w_bf_cifrador)

def buscarBlowFish(palabra):
    try:
        w_bf_cipher = CifradorBlowFish(CLAVE_ENCRIPTADO)
        s_bf_cipher = CifradorBlowFish(CLAVE_ENCRIPTADO)
        palabra_justificada = palabra.ljust(32, '.') 
        cifradoBuscar = w_bf_cipher.cifrar(palabra_justificada)
        ruta='./salida/BlowFish'
        return buscar_ficheros(cifradoBuscar, ruta, s_bf_cipher)
    except EOFError:
        print ('\nError\n')
        sys.exit(0)

############ CIFRADO MEDIANTE RC2 ##################
        
class CifradorRC2:
    def __init__(self, clave):
        self.clave = clave

    def cifrar(self, datos):
        iv = texto_aleatorio_8
        cifrador =  ARC2.new(self.clave, ARC2.MODE_CFB, iv)# https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
        return cifrador.encrypt(datos)

    def descifrar(self, encriptado):
        code = base64.b64decode(encriptado)
        iv = code[:8]
        cifrador =  ARC2.new(self.clave, ARC2.MODE_CFB, iv)
        return unpad(cifrador.decrypt(encriptado[8:]))


def encriptarficheroRC2():
    cifrado_de_fujo = Cifrado_de_fujo(CLAVE_CIFRADO_FLUJO)
    w_RC2_cifrador = CifradorRC2(CLAVE_ENCRIPTADO)
    s_RC2_cifrador = CifradorRC2(CLAVE_ENCRIPTADO)
    ruta = './salida/RC2'
    return encriptar_fichero(cifrado_de_fujo, ruta, s_RC2_cifrador, w_RC2_cifrador)

def buscarRC2(palabra):
        try:
            w_RC2_cipher = CifradorRC2(CLAVE_ENCRIPTADO)
            s_RC2_cipher = CifradorRC2(CLAVE_ENCRIPTADO)
            palabra_justificada = palabra.ljust(32, '.') 
            cifradoBuscar = w_RC2_cipher.cifrar(palabra_justificada)
            ruta='./salida/RC2'
            return buscar_ficheros(cifradoBuscar,ruta, s_RC2_cipher)
        except EOFError:
            print('\nError\n')
            sys.exit(0)
        
############ CIFRADO MEDIANTE AES ################## 
        
class CifradorAES:
    def __init__(self, clave):
        self.claveAES = clave

    def cifrar(self, datos):
        iv = texto_aleatorio_16
        cifrador = AES.new(self.claveAES,AES.MODE_CBC,iv) # https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
        return cifrador.encrypt(datos)

    def descifrar(self, encriptado):
        code = base64.b64decode(encriptado)
        iv = code[:16]
        cifrador = AES.new(self.claveAES, AES.MODE_CBC, iv)
        return unpad(cifrador.decrypt(encriptado[16:]))
    

def encriptarficheroAES():
    cifrado_de_fujo = Cifrado_de_fujo(CLAVE_CIFRADO_FLUJO)
    w_aes_cifrador = CifradorAES(CLAVE_ENCRIPTADO)
    s_aes_cifrador = CifradorAES(CLAVE_ENCRIPTADO)
    ruta = './salida/AES'
    return encriptar_fichero(cifrado_de_fujo, ruta, s_aes_cifrador, w_aes_cifrador)

def buscarAES(palabra):
    try:
        w_aes_cipher = CifradorAES(CLAVE_ENCRIPTADO)
        s_aes_cipher = CifradorAES(CLAVE_ENCRIPTADO)
        palabra_justificada = palabra.ljust(32, '.') 
        cifradoBuscar = w_aes_cipher.cifrar(palabra_justificada)
        ruta='./salida/AES'
        return buscar_ficheros(cifradoBuscar, ruta, s_aes_cipher)
    except EOFError:
        print('\nError\n')
        sys.exit(0)


############ Funciones auxiliares de menu ##################   
       
def pedir_palabra():
    palabra = input('\nPalabra a buscar: ')
    while (not palabra):
        palabra = input('Introduzca una palabra:')
    return palabra

def mostar_resultado(resultado):
    if(len(resultado)==0):
        print('No encontrado')
    else:
        print("Ha sido encontrado en los siguientes ficheros: ", resultado)

def menu_busqueda():
    tipo=0
    resultados=[]
    while(not(int(tipo)==3)):
        tipo = input('\n Que Cifrador desea usar: \n 0.AES \n 1.BlowFish \n 2.RC2 \n 3.Salir \n')
        if (int(tipo)==0):
            palabra=pedir_palabra()
            resultados=buscarAES(palabra)
        if (int(tipo)==1):
            palabra = pedir_palabra()
            resultados=buscarBlowFish(palabra)
        if (int(tipo)==2):
            palabra = pedir_palabra()
            resultados=buscarRC2(palabra)
        if (int(tipo)==3):
            return False
        mostar_resultado(resultados)

def mostrar_tabla_busq(datos_palabra):
    print(datos_palabra)
    longitud_fichero=[]
    tiempos_AES=[]
    tiempos_BlowFish=[]
    tiempos_RC2=[]
    for i in range(len(datos_palabra)):
        longitud_fichero.append(datos_palabra[i][0])
        tiempos_AES.append(datos_palabra[i][1])
        tiempos_RC2.append(datos_palabra[i][2])
        tiempos_BlowFish.append(datos_palabra[i][3])
    pyplot.plot(longitud_fichero,tiempos_AES,'bo')
    pyplot.plot(longitud_fichero,tiempos_BlowFish,'ro')
    pyplot.plot(longitud_fichero,tiempos_RC2,'go')
    green_patch = mpatches.Patch(color='green', label='BlowFish')
    red_patch = mpatches.Patch(color='red', label='RC2')
    blue_patch = mpatches.Patch(color='blue', label='AES')
    pyplot.legend(handles=[red_patch,green_patch,blue_patch])
    pyplot.show()

def busquedas():
    vector_busquedas=['nombre0', 'nombre1', 'nombre2', 'nombre3', 'nombre4', 'nombre5', 'nombre6', 'nombre7', 'nombre8', 'nombre9', 'nombre10', 'nombre11', 'nombre12', 'nombre13', 'nombre14', 'nombre15', 'nombre16', 'nombre17', 'nombre18', 'nombre19', 'nombre20', 'nombre21', 'nombre22', 'nombre23', 'nombre24', 'nombre25', 'nombre26', 'nombre27', 'nombre28', 'nombre29', 'nombre30', 'nombre31', 'nombre32', 'nombre33', 'nombre34', 'nombre35', 'nombre36', 'nombre37', 'nombre38', 'nombre39', 'nombre40', 'nombre41', 'nombre42', 'nombre43', 'nombre44', 'nombre45', 'nombre46', 'nombre47', 'nombre48', 'nombre49']
    resultados_AES=[]
    resultados_RC2=[]
    resultados_BF=[]
    datos=[]
    for i in range(len(vector_busquedas)):
        resultados_AES=buscarAES(vector_busquedas[i])
        resultados_RC2=buscarBlowFish(vector_busquedas[i])
        resultados_BF=buscarRC2(vector_busquedas[i])
        if(len(resultados_AES[0])!=0):
            datos_palabra=[resultados_AES[0][0],resultados_AES[1][0],resultados_RC2[1][0],resultados_BF[1][0]]
            datos.append(datos_palabra)
    mostrar_tabla_busq(datos)    
    
############ MAIN ################## 
        
inicio=time.time()            
datos_AES=encriptarficheroAES()
fin=time.time()
print('Tiempo total invertido en encriptarAES',fin-inicio)
inicio=time.time()  
datos_BlowFish=encriptarficheroRC2()
fin=time.time()
print('Tiempo total invertido en encriptarRC2',fin-inicio)
inicio=time.time()  
datos_RC2=encriptarficheroBlowFish()
fin=time.time()
print('Tiempo total invertido en encriptarBlowFish',fin-inicio)
mostrar_datos(datos_AES,datos_BlowFish,datos_RC2)
busquedas()
ejecucion=True
while (ejecucion):
    ejecucion=menu_busqueda()