import socket
import sys
import ast
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

def rot(n):
    from string import ascii_lowercase as lc, ascii_uppercase as uc
    lookup = str.maketrans(lc + uc, lc[n:] + lc[:n] + uc[n:] + uc[:n])
    return lambda s: s.translate(lookup)

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 10000)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)

# Datos del Server para Gamal
p = 41
g = 24
a = 7
# Key
k = (g**a) % p

# Datos para AES con diffie hellman
g2 = 12054623
p2 = 23119651
a2 = 21703

A = (g2**a2)%p2

# otra vez para evitar problemas con el largo de la llave
salt= 'Y33lhdcyn2ceqmw3lmdldk12'

# Listen for incoming connections
sock.listen(1)

# Variable para verificar que la parte 1 ha ocurrido
M_reciv = False
M_reenv = False

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        print('connection from', client_address)
        
        # Enviamos la clave publica
        print('Enviando la clave publica a client')
        Cb =bytes(str(k), 'utf-8')
        print('Enviando {!r}'.format(Cb))
        connection.sendall(Cb)

        # Receive the data in small chunks
        while True:
            if M_reciv == False:
                data = connection.recv(16)
            else:
                pass
            if data and M_reciv == False:
                cm = str(data.decode("utf-8"))

                # Revisamos si llego más mensaje
                if cm[len(cm)-1] != "|":
                    while True:
                        data = connection.recv(16)
                        if data:
                            cm+= data.decode("utf-8")
                        else:
                            break
                    
                try:
                    # Desencriptamos el mensaje
                    n = -1*k
                    cm = cm[:-1]
                    mtrad = rot(n)(cm)
                    print('recivido:',mtrad)
                    # Volteamos el mesnsaje
                    mtinv = mtrad[::-1]
                    txt = open("mensaje_de_salida.txt","w")
                    menEntrtxt = txt.write(mtinv+"\n")
                    txt.close()

                    M_reciv = True
                except:
                    # Espero que nunca salga
                    print("ha ocirrido un error de formato")
                    
            elif M_reciv != 'Reneviando':
                # Enviamos valores para diffie hellman
                num=str(g2)+","+str(p2)+","+str(A)
                mes =bytes(num, 'utf-8') #G,P,A
                print('sending {!r}'.format(mes))
                connection.sendall(mes)

                amount_received = 0
                # Esperamos valor B de client
                while amount_received <= 0:
                    try:
                        data = connection.recv(16)
                        amount_received += len(data)
                        print('received {!r}'.format(data))

                        # resuesta (B) a datos
                        res = data.decode("utf-8")
                        
                        B=int(res)
                        
                        # hacemos llave
                        K = (B**a2)%p2
                        print("key is: ",K)
                        M_reciv = 'Reneviando'
                    except:
                        pass
     
            elif M_reenv == False and M_reciv == 'Reneviando':
                txt = open("mensaje_de_salida.txt","r")
                m = txt.read()
                txt.close()
                
                # Preparamos la llave y encriptamos con AES el mensaje
                key = bytes(str(K)+salt, 'utf-8')
                cipher = AES.new(key, AES.MODE_CBC)
                ciphertext= cipher.encrypt(bytes(m, 'utf-8'))
                
                iv = b64encode(cipher.iv).decode('utf-8')
                ct = b64encode(ciphertext).decode('utf-8')
                # Enviamos a client
                
                mes =bytes(iv+'|'+ct, 'utf-8') #Initialization Vector y el mensaje
                print('sending iv em {!r}'.format(mes))
                connection.sendall(mes)

                M_reenv = True
            else:
                print('no data from', client_address)
                break

    finally:
        # Clean up the connection
        connection.close()
