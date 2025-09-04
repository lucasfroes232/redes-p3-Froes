import random
import os
import struct
from iputils import *

class CamadaEnlace:
    ignore_checksum = False
    def __init__(self):
        self.callback = None
        self.fila = []
    def registrar_recebedor(self, callback):
        self.callback = callback
    def enviar(self, datagrama, next_hop):
        self.fila.append((datagrama, next_hop))

def rand_ip():
    return '%d.%d.%d.%d'%tuple(random.randint(1, 255) for i in range(4))
