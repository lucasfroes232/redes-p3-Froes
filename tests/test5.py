import unittest
import random
import struct
from iputils import *
from ip import IP

from tests.common import *

class TestStep5(unittest.TestCase):
    def test_step5(self):
        enlace = CamadaEnlace()
        rede = IP(enlace)

        def enviar_datagrama(dest, ttl, gw, myip=None):
            datagrama = b'E\x00\x00\x14\x00\x00\x00\x00'+bytes([ttl])+b'\x06\x00\x00\x01\x02\x03\x04' + str2addr(dest)
            self.assertEqual(len(datagrama), 20)
            datagrama = datagrama[:-10] + struct.pack('!H',calc_checksum(datagrama)) + datagrama[-8:]
            enlace.callback(datagrama)
            if ttl == 1:
                self.assertEqual(len(enlace.fila), 1, msg='Deveria ter vindo um erro ICMP ao descartar o pacote')
                datagram_, next_hop = enlace.fila.pop()
                dscp, ecn, identification, flags, frag_offset, ttl_, proto, \
                       src_addr, dst_addr, payload = read_ipv4_header(datagram_, verify_checksum=True)
                self.assertEqual(proto, IPPROTO_ICMP, msg='O datagrama deveria ter sido descartado, a única coisa que poderia ter sido mandada era um erro ICMP')
                self.assertEqual(dst_addr, '1.2.3.4', msg='Endereço de destino incorreto')
                if myip is not None:
                    self.assertEqual(src_addr, myip, msg='Endereço de origem incorreto')
                self.assertEqual(dscp, 0, msg='DSCP deve ser 0')
                self.assertEqual(ecn, 0, msg='ECN deve ser 0')
                self.assertEqual(flags, 0, msg='Flags deve ser 0')
                self.assertGreaterEqual(ttl_, 15, msg='TTL muito baixo')
                self.assertEqual(next_hop, gw, msg='Datagrama encaminhado para next_hop incorreto')
                self.assertEqual(calc_checksum(payload), 0, msg='Seu checksum está incorreto')
                icmp_type, icmp_code = struct.unpack('!BB', payload[:2])
                self.assertEqual(icmp_type, 11, msg='Tipo ICMP deveria ser 11')
                self.assertEqual(icmp_code, 0, msg='Código ICMP deveria ser 0')
                self.assertEqual(payload[8:], datagrama[:28], msg='ICMP deve conter os primeiros 28 bytes do datagrama descartado')
            else:
                self.assertEqual(len(enlace.fila), 1, msg='Só foi recebido um datagrama, mas foi encaminhado mais de um')
                datagrama, next_hop = enlace.fila.pop()
                self.assertEqual(len(datagrama), 20, msg='O tamanho mudou ao ser encaminhado')
                dscp, ecn, identification, flags, frag_offset, ttl_, proto, \
                       src_addr, dst_addr, payload = read_ipv4_header(datagrama, verify_checksum=True)
                self.assertEqual(ttl_, ttl - 1, msg=f'Foi utilizado um TTL de {ttl_}, mas deveria ter sido {ttl-1}')
                self.assertEqual(dscp, 0, msg='DSCP deve ser 0')
                self.assertEqual(ecn, 0, msg='ECN deve ser 0')
                self.assertEqual(identification, 0, msg='Identification deve ser 0')
                self.assertEqual(flags, 0, msg='Flags deve ser 0')
                self.assertEqual(frag_offset, 0, msg='Frag offset deve ser 0')
                self.assertEqual(proto, IPPROTO_TCP, msg='Protocolo deve ser TCP')
                self.assertEqual(src_addr,'1.2.3.4', msg='Endereço de origem incorreto')
                self.assertEqual(dst_addr,dest, msg='Endereço de destino incorreto')
                self.assertEqual(len(payload), 0, msg='Payload deveria estar vazio')
                self.assertEqual(next_hop, gw, msg='Datagrama encaminhado para next_hop incorreto')

        gw = rand_ip()
        myip = rand_ip()
        rede.definir_endereco_host(myip)
        rede.definir_tabela_encaminhamento([
            ('0.0.0.0/0', gw),
        ])
        for i in range(128):
            enviar_datagrama(rand_ip(), random.randint(1, 255), gw, myip)
            for j in range(random.randint(0, 2)):
                enviar_datagrama(rand_ip(), 1, gw, myip)
