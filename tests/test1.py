import unittest
import random
from tcputils import *
from ip import IP

from tests.common import *

class TestStep1(unittest.TestCase):
    def test_step1(self):
        enlace = CamadaEnlace()
        rede = IP(enlace)

        def enviar_datagrama(dest):
            datagrama = b'E\x00\x00\x14\x00\x00\x00\x00@\x06\x00\x00\x01\x02\x03\x04' + str2addr(dest)
            self.assertEqual(len(datagrama), 20)
            enlace.callback(datagrama[:-10] + struct.pack('!H',calc_checksum(datagrama)) + datagrama[-8:])
            self.assertEqual(len(enlace.fila), 1, msg='Só foi recebido um datagrama, mas foi encaminhado mais de um')
            datagrama, next_hop = enlace.fila.pop()
            self.assertEqual(len(datagrama), 20, msg='O tamanho mudou ao ser encaminhado')
            dscp, ecn, identification, flags, frag_offset, ttl, proto, \
                   src_addr, dst_addr, payload = read_ipv4_header(datagrama, verify_checksum=True)
            self.assertEqual(dscp, 0, msg='DSCP deve permanecer 0')
            self.assertEqual(ecn, 0, msg='ECN deve permanecer 0')
            self.assertEqual(identification, 0, msg='Identification deve permanecer 0')
            self.assertEqual(flags, 0, msg='Flags deve permanecer 0')
            self.assertEqual(frag_offset, 0, msg='Frag offset deve permanecer 0')
            self.assertIn(ttl, {63,64}, msg='TTL inesperado')
            self.assertEqual(proto, IPPROTO_TCP, msg='Protocolo deve ser TCP')
            self.assertEqual(src_addr,'1.2.3.4', msg='Endereço de origem incorreto')
            self.assertEqual(dst_addr,dest, msg='Endereço de destino incorreto')
            self.assertEqual(len(payload), 0, msg='Payload deveria estar vazio')
            return next_hop

        gw = rand_ip()
        rede.definir_tabela_encaminhamento([
            ('0.0.0.0/0', gw),
        ])
        for i in range(16):
            next_hop = enviar_datagrama(rand_ip())
            self.assertEqual(next_hop, gw, msg='Datagrama encaminhado para next_hop incorreto')

        # Teste máscaras /1
        for i in range(16):
            gw1 = rand_ip()
            gw2 = rand_ip()
            rede.definir_tabela_encaminhamento([
                ('0.0.0.0/1', gw1),
                ('128.0.0.0/1', gw2),
            ])
            dest = rand_ip()
            next_hop = enviar_datagrama(dest)
            first_bit = int(dest.split('.')[0]) >> 7
            if first_bit == 0:
                self.assertEqual(next_hop, gw1, msg='Datagrama encaminhado para next_hop incorreto')
            else:
                self.assertEqual(next_hop, gw2, msg='Datagrama encaminhado para next_hop incorreto')

        # Teste máscaras variadas
        for j in range(8):
            gw1, gw2, gw3, gw4, gw5, gw6, gw7, gw8, gw9, gw10 = tuple(rand_ip() for i in range(10))
            tbl = [
                ('200.0.0.0/8', gw1),
                ('201.0.0.0/8', gw2),
                ('202.0.0.0/9', gw3),
                ('202.128.0.0/9', gw4),
                ('203.98.0.0/18', gw5),
                ('203.98.192.0/18', gw6),
                ('204.54.91.0/27', gw7),
                ('204.54.91.160/27', gw8),
                ('1.2.3.4/32', gw9),
                ('5.6.7.8/32', gw10),
            ]
            dic = {gw: cidr for cidr, gw in tbl}
            random.shuffle(tbl)
            rede.definir_tabela_encaminhamento(tbl)
            a, b, c = tuple(random.randint(0, 255) for i in range(3))
            tests = [
                ('200.%d.%d.%d' % (a, b, c), gw1),
                ('201.%d.%d.%d' % (a, b, c), gw2),
                ('202.%d.%d.%d' % (a & ~128, b, c), gw3),
                ('202.%d.%d.%d' % (a | 128, b, c), gw4),
                ('203.98.%d.%d' % (a & ~192, b), gw5),
                ('203.98.%d.%d' % (a | 192, b), gw6),
                ('204.54.91.%d' % (a >> 3), gw7),
                ('204.54.91.%d' % (160 | (a >> 3)), gw8),
                ('204.54.91.%d' % (192 | (a >> 3)), None),
                ('204.54.91.%d' % (64 | (a >> 3)), None),
                ('204.54.91.%d' % (128 | (a >> 3)), None),
                ('1.2.3.4', gw9),
                ('5.6.7.8', gw10),
                ('9.10.11.12', None),
            ]
            random.shuffle(tests)
            for dest, expected_gw in tests:
                got_gw = enviar_datagrama(dest)
                self.assertEqual(got_gw, expected_gw, msg=f'Datagrama destinado a {dest} deveria ter casado com {expected_gw}, mas casou com {got_gw}')

        # Teste com tabela vazia
        rede.definir_tabela_encaminhamento([])
        for i in range(8):
            dest = rand_ip()
            next_hop = enviar_datagrama(dest)
            self.assertIsNone(next_hop, msg=f'Com tabela vazia, next_hop deveria ser None para {dest}, mas foi {next_hop}')

        # Teste com rota para o próprio endereço
        myip = rand_ip()
        rede.definir_endereco_host(myip)
        rede.definir_tabela_encaminhamento([
            ('0.0.0.0/0', rand_ip()),
            (myip + '/32', rand_ip()),
        ])
        # Para dst == meu_endereco, deve ir para host mode, não rotear
        # Então, fila fica vazia, mas callback seria chamado se definido
        datagrama = b'E\x00\x00\x14\x00\x00\x00\x00@\x06\x00\x00\x01\x02\x03\x04' + str2addr(myip)
        datagrama = datagrama[:-10] + struct.pack('!H', calc_checksum(datagrama)) + datagrama[-8:]
        enlace.callback(datagrama)
        self.assertEqual(len(enlace.fila), 0, msg='Datagrama para próprio endereço deve ser processado como host, não roteado')
