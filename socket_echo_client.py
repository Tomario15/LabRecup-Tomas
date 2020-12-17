import socket
import sys
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

def rot(n):
    from string import ascii_lowercase as lc, ascii_uppercase as uc
    lookup = str.maketrans(lc + uc, lc[n:] + lc[:n] + uc[n:] + uc[:n])
    return lambda s: s.translate(lookup)

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10000)
print('connecting to {} port {}'.format(*server_address))
sock.connect(server_address)

# Datos del Client (emisor del mensaje)
# Mensaje
txt = open("mensaje_de_entrada.txt","r")
m = txt.read()
txt.close()

# Datos para AES con diffie hellman
M_reenv = False
b = 123421
K = 0
# otra vez para evitar problemas con el largo de la llave
salt= 'Y33lhdcyn2ceqmw3lmdldk12'

try:    

    # Look for the response
    amount_received = 0

    while amount_received <= 0:
        data = sock.recv(16)
        amount_received += len(data)
        print('Recivido {!r}'.format(data))
    ms = data.decode("utf-8")  #mensaje de server

    # Revisamos si el mensaje obtenido es la llave publica
    try:
        k = int(ms)
        # Encriptamos con rot(n) con n = k
        menc = rot(k)(str(m))
        # Enviamos mensaje
        message = bytes(menc+str("|"), 'utf-8')
            
        print('Enviando {!r}'.format(message))
        sock.sendall(message)
    except:
        print("Ha ocurrido un error al recivir la clave publica")
        pass

    while K == 0: # se recive (G,P,A)
        dt = sock.recv(32)
        if dt:
            print('received {!r}'.format(dt))
            #mensaje (G,P,A) a datos
            men = dt.decode("utf-8").split(",")
        
            try:
                G = int(men[0])
                P = int(men[1])
                A = int(men[2])

                # Calculamos B y lo enviamos
                B = str((G**b)%P)
                Bmens = bytes(B, 'utf-8')
                print('sending {!r}'.format(Bmens))
                sock.sendall(Bmens)
            
                # hacemos llave
                K = (A**b)%P

            except:
                pass
        else:
            pass
        
    print('watenig')
    while M_reenv == False:
        # Recibimos el mensaje de vuelta
        try:
            data = sock.recv(64)
            amount_received += len(data)
            print('received iv em {!r}'.format(data))
 
            mreg = data.decode("utf-8").split('|')
           
            # Definimos los datos
            key = bytes(str(K)+salt, 'utf-8')
            iv = b64decode(mreg[0])
            ciphertext = b64decode(mreg[1])
            
            # Desencriptamos con AES
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext)

            mtrad = plaintext.decode('utf-8')
            #print("mrecib:",mtrad)
            # Volteamos el mesnsaje
            mtinv = mtrad[::-1]
            txt = open("mensaje_de_vuelta.txt","w")
            menEntrtxt = txt.write(mtinv+"\n")
            txt.close()

            M_reenv = True
        except:
            print('oh oh')
            break
        
finally:
    print('closing socket')
    sock.close()
