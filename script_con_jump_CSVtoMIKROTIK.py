#########################################################################
#script para convertir reglas de firewall de formato csv a mikrotik
#el formato del archivo csv deber ser 
#datos[0],datos[1],datos[2],datos[3],datos[4],datos[5],datos[6],datos[7]
#datos[0]= # o NULL
#datos[1]= accept or drop
#datos[2]= ip de origen
#datos[3]= ip de destino
#datos[4]= comentario
#datos[5]= protocolo
#datos[6]= puerto
#datos[7]= cadena apra el jump
########################################################################
import csv
fila =0
comuna=0
conta =0
f = open("reglas.rsc", "a")
f.write("/ip firewall filter\n")
with open('reglasjump.csv') as File:
        reader = csv.reader(File)
        for datos in reader:
                fila = fila + 1
                if(fila > conta):
                        conta = conta + 1
                        if (datos[0]!="#"):
                                if(datos[1]=="drop"):
                                        if(datos[5]=='' and datos[6]==''):
                                                f.write("add action=" + datos[1] +" comment=\""+ datos[4]+"\" dst-address="+datos[3]+ " src-address="+datos[2]+"\n")
                                        if(datos[5]!='' and datos[6]==''):
                                                f.write("add action=" + datos[1] +" comment=\""+ datos[4]+"\" dst-address="+datos[3] +" protocol="+datos[5]+ " src-address="+datos[2]+"\n")
                                        if(datos[5]!='' and datos[6]!=''):
                                                f.write("add action=" + datos[1] +" comment=\""+ datos[4]+"\" dst-address="+datos[3] +" dst-port="+datos[6]+" protocol="+datos[5]+ " src-address="+datos[2]+"\n")
                                else:                                 
                                        if(datos[5]=='' and datos[6]==''):
                                                f.write("add action=" + datos[1] +" chain="+datos[7]+ " comment=\""+ datos[4]+"\" dst-address="+datos[3]+ " src-address="+datos[2]+"\n")
                                        if(datos[5]!='' and datos[6]==''):
                                                f.write("add action=" + datos[1] +" chain="+datos[7]+ " comment=\""+ datos[4]+"\" dst-address="+datos[3] +" protocol="+datos[5]+ " src-address="+datos[2]+"\n")
                                        if(datos[5]!='' and datos[6]!=''):
                                                f.write("add action=" + datos[1] +" chain="+datos[7]+ " comment=\""+ datos[4]+"\" dst-address="+datos[3] +" dst-port="+datos[6]+" protocol="+datos[5]+ " src-address="+datos[2]+"\n")
                        else:
                                if(datos[1]=="drop"):
                                        if(datos[5]=='' and datos[6]==''):
                                                f.write("add action=" + datos[1] +" comment=\""+ datos[4]+"\" disabled=yes dst-address="+datos[3]+ " src-address="+datos[2]+"\n")
                                        if(datos[5]!='' and datos[6]==''):
                                                f.write("add action=" + datos[1] +" comment=\""+ datos[4]+"\" disabled=yes dst-address="+datos[3] +" protocol="+datos[5]+ " src-address="+datos[2]+"\n")
                                        if(datos[5]!='' and datos[6]!=''):
                                                f.write("add action=" + datos[1] +" comment=\""+ datos[4]+"\" disabled=yes dst-address="+datos[3] +" dst-port="+datos[6]+" protocol="+datos[5]+ " src-address="+datos[2]+"\n")
                                else:
                                        if(datos[5]=='' and datos[6]==''):
                                                f.write("add action=" + datos[1] +" chain="+datos[7]+ " comment=\""+ datos[4]+"\" disabled=yes dst-address="+datos[3]+ " src-address="+datos[2]+"\n")
                                        if(datos[5]!='' and datos[6]==''):
                                                f.write("add action=" + datos[1] +" chain="+datos[7]+ " comment=\""+ datos[4]+"\" disabled=yes dst-address="+datos[3] +" protocol="+datos[5]+ " src-address="+datos[2]+"\n")
                                        if(datos[5]!='' and datos[6]!=''):
                                                f.write("add action=" + datos[1] +" chain="+datos[7]+ " comment=\""+ datos[4]+"\" disabled=yes dst-address="+datos[3] +" dst-port="+datos[6]+" protocol="+datos[5]+ " src-address="+datos[2]+"\n")
f.close()