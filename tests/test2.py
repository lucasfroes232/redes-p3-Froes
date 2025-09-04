import unittest
import random
import os
import struct
from iputils import *
from ip import IP

from tests.common import *

class TestStep2(unittest.TestCase):
    def test_step2(self):
        enlace = CamadaEnlace()
        rede = IP(enlace)

        myip = rand_ip()
        rede.definir_endereco_host(myip)
        gw = rand_ip()
        rede.definir_tabela_encaminhamento([
            ('0.0.0.0/0', gw),
        ])

        for i in range(64):
            dest = rand_ip()
            segmento = os.urandom(random.randint(0, 1024))
            rede.enviar(segmento, dest)
            self.assertEqual(len(enlace.fila), 1, msg='Só foi enviado um datagrama, mas foi encaminhado mais de um')
            datagrama, next_hop = enlace.fila.pop()
            self.assertEqual(len(datagrama), 20 + len(segmento), msg='Datagrama com tamanho inesperado')
            dscp, ecn, identification, flags, frag_offset, ttl, proto, \
                   src_addr, dst_addr, payload = read_ipv4_header(datagrama, verify_checksum=True)
            self.assertEqual(dscp, 0, msg='DSCP deve ser 0')
            self.assertEqual(ecn, 0, msg='ECN deve ser 0')
            self.assertEqual(flags, 0, msg='Flags deve ser 0')
            self.assertEqual(frag_offset, 0, msg='Frag offset deve ser 0')
            self.assertGreaterEqual(ttl, 15, msg=f'O seu TTL de {ttl} é muito baixo. Recomendamos 64')
            self.assertEqual(proto, IPPROTO_TCP, msg='Protocolo deve ser TCP')
            self.assertEqual(src_addr, myip, msg='Produza datagramas com meu_endereco como remetente')
            self.assertEqual(dst_addr, dest, msg=f'Pedimos para enviar para {dest}, mas foi enviado para {dst_addr}')
            self.assertEqual(payload, segmento, msg='Payload não bate com o segmento pedido')
            self.assertEqual(next_hop, gw, msg=f'O datagrama deveria ter sido encaminhado via {gw}, mas foi via {next_hop}')

        # Teste com payload vazio
        dest = rand_ip()
        segmento = b''
        rede.enviar(segmento, dest)
        self.assertEqual(len(enlace.fila), 1)
        datagrama, next_hop = enlace.fila.pop()
        self.assertEqual(len(datagrama), 20, msg='Datagrama com payload vazio deve ter 20 bytes')
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
               src_addr, dst_addr, payload = read_ipv4_header(datagrama, verify_checksum=True)
        self.assertEqual(payload, b'', msg='Payload deve estar vazio')

        # Teste com payload grande
        dest = rand_ip()
        segmento = os.urandom(65000)
        rede.enviar(segmento, dest)
        self.assertEqual(len(enlace.fila), 1)
        datagrama, next_hop = enlace.fila.pop()
        self.assertEqual(len(datagrama), 20 + 65000, msg='Datagrama com payload grande deve ter tamanho correto')
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
               src_addr, dst_addr, payload = read_ipv4_header(datagrama, verify_checksum=True)
        self.assertEqual(len(payload), 65000, msg='Payload deve ter 65000 bytes')

        # Teste sem meu_endereco definido
        enlace2 = CamadaEnlace()
        rede2 = IP(enlace2)
        rede2.definir_endereco_host('0.0.0.0')  # Definir como 0.0.0.0
        gw2 = rand_ip()
        rede2.definir_tabela_encaminhamento([('0.0.0.0/0', gw2)])
        dest = rand_ip()
        segmento = os.urandom(100)
        rede2.enviar(segmento, dest)
        self.assertEqual(len(enlace2.fila), 1)
        datagrama, next_hop = enlace2.fila.pop()
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
               src_addr, dst_addr, payload = read_ipv4_header(datagrama, verify_checksum=True)
        self.assertEqual(src_addr, '0.0.0.0', msg='Sem meu_endereco definido, src_addr deve ser 0.0.0.0')
