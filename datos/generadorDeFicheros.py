
def generador_ejemplos():
       for i in range(50):
           nombre="zfichero"+str(i)
           f=open(nombre,"w")
           j=0
           while j<i*1000:
               f.write("palabra\n")
               j=j+1
               if(j==int((i*1000)/2)):
                   f.write("nombre"+str(i)+"\n")
           f.close()  
           
def vector_nombres():
    vector=[]
    for i in range(50):  
        vector.append("nombre"+str(i))
    print(vector)
    
generador_ejemplos()
#vector_nombres()