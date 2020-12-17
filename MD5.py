import hashlib 

txt = open("mensaje_de_entrada.txt","r")
m = txt.read()
txt.close()

result = hashlib.md5(bytes(m,'utf-8'))

# printing the equivalent byte value. 
print("mensaje_de_entrada.txt md5 is : ", end ="") 
print(result.hexdigest())
#====================================================
txt = open("mensaje_de_salida.txt","r")
m = txt.read()
txt.close()

result = hashlib.md5(bytes(m,'utf-8'))

# printing the equivalent byte value. 
print("mensaje_de_salida.txt md5 is : ", end ="") 
print(result.hexdigest())
#====================================================
txt = open("mensaje_de_vuelta.txt","r")
m = txt.read()
txt.close()

result = hashlib.md5(bytes(m,'utf-8'))

# printing the equivalent byte value. 
print("mensaje_de_vuelta.txt md5 is : ", end ="") 
print(result.hexdigest())
