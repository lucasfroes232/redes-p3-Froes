import unittest
import random
from iputils import *
from ip import IP

from tests.common import *

class TestStep3(unittest.TestCase):
    def test_step3(self):
        enlace = CamadaEnlace()
        rede = IP(enlace)

        # Teste /1 masks
        for i in range(16):
            gw1 = rand_ip()
            gw2 = rand_ip()
            rede.definir_tabela_encaminhamento([
                ('0.0.0.0/1', gw1),
                ('128.0.0.0/1', gw2),
            ])
            dest = rand_ip()
            datagrama = b'E\x00\x00\x14\x00\x00\x00\x00@\x06\x00\x00\x01\x02\x03\x04' + str2addr(dest)
            self.assertEqual(len(datagrama), 20)
            enlace.callback(datagrama[:-10] + struct.pack('!H',calc_checksum(datagrama)) + datagrama[-8:])
            self.assertEqual(len(enlace.fila), 1, msg='Só foi recebido um datagrama, mas foi encaminhado mais de um')
            _, next_hop = enlace.fila.pop()
            first_bit = int(dest.split('.')[0])>>7
            if first_bit == 0:
                self.assertEqual(next_hop, gw1, msg='Datagrama encaminhado para next_hop incorreto')
            else:
                self.assertEqual(next_hop, gw2, msg='Datagrama encaminhado para next_hop incorreto')

        # Teste máscaras variadas com rota padrão definida
        for j in range(8):
            gw1, gw2, gw3, gw4, gw5, gw6, gw7, gw8, gw9, gw10 = tuple(rand_ip() for i in range(10))
            tbl = [
                ('200.0.0.0/7', gw1),
                ('201.0.0.0/8', gw2),
                ('202.0.0.0/8', gw3),
                ('202.128.0.0/9', gw4),
                ('203.98.0.0/16', gw5),
                ('203.98.192.0/18', gw6),
                ('204.54.91.0/27', gw7),
                ('204.54.91.160/27', gw8),
                ('1.2.3.4/32', gw9),
                ('0.0.0.0/0', gw10),
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
                ('204.54.91.%d' % (192 | (a >> 3)), gw10),
                ('204.54.91.%d' % (64 | (a >> 3)), gw10),
                ('204.54.91.%d' % (128 | (a >> 3)), gw10),
                ('1.2.3.4', gw9),
                ('5.6.7.8', gw10),
                ('9.10.11.12', gw10),
            ]
            random.shuffle(tests)
            for dest, expected_gw in tests:
                datagrama = b'E\x00\x00\x14\x00\x00\x00\x00@\x06\x00\x00\x01\x02\x03\x04' + str2addr(dest)
                self.assertEqual(len(datagrama), 20)
                enlace.callback(datagrama[:-10] + struct.pack('!H', calc_checksum(datagrama)) + datagrama[-8:])
                self.assertEqual(len(enlace.fila), 1, msg='Só foi recebido um datagrama, mas foi encaminhado mais de um')
                _, next_hop = enlace.fila.pop()
                self.assertEqual(next_hop, expected_gw, msg=f'Datagrama destinado a {dest} deveria ter casado com {expected_gw}, mas foi para {next_hop}')

        # Teste máscaras variadas sem rota padrão definida
        for j in range(8):
            gw1, gw2, gw3, gw4, gw5 = tuple(rand_ip() for i in range(5))
            tbl = [
                ('200.0.0.0/8', gw1),
                ('200.1.0.0/16', gw2),
                ('200.1.128.0/17', gw3),
                ('200.1.129.0/24', gw4),
                ('200.1.130.0/24', gw5),
            ]
            dic = {gw: cidr for cidr, gw in tbl}
            random.shuffle(tbl)
            rede.definir_tabela_encaminhamento(tbl)
            a, b, c, d = tuple(random.randint(0, 255) for i in range(4))
            tests = [
                ('200.0.%d.%d' % (b, c), gw1),
                ('200.%d.%d.%d' % (min(a + 2, 255), b, c), gw1),
                ('200.1.%d.%d' % (b >> 1, c), gw2),
                ('200.1.128.%d' % c, gw3),
                ('200.1.129.%d' % c, gw4),
                ('200.1.130.%d' % c, gw5),
                ('200.1.%d.%d' % (max(131, b), c), gw3),
                ('%d.%d.%d.%d' % (min(a, 199), b, c, d), None),
                ('%d.%d.%d.%d' % (max(a, 201), b, c, d), None),
            ]
            random.shuffle(tests)
            for dest, expected_gw in tests:
                datagrama = b'E\x00\x00\x14\x00\x00\x00\x00@\x06\x00\x00\x01\x02\x03\x04' + str2addr(dest)
                self.assertEqual(len(datagrama), 20)
                enlace.callback(datagrama[:-10] + struct.pack('!H', calc_checksum(datagrama)) + datagrama[-8:])
                if expected_gw is None:
                    self.assertEqual(len(enlace.fila), 1, msg='Datagrama deveria ter sido encaminhado mesmo sem match exato')
                    _, next_hop = enlace.fila.pop()
                    self.assertIsNone(next_hop, msg=f'Datagrama destinado a {dest} deveria ter next_hop None, mas foi {next_hop}')
                else:
                    self.assertEqual(len(enlace.fila), 1, msg='Só foi recebido um datagrama, mas foi encaminhado mais de um')
                    _, next_hop = enlace.fila.pop()
                    self.assertEqual(next_hop, expected_gw, msg=f'Datagrama destinado a {dest} deveria ter casado com {expected_gw}, mas foi para {next_hop}')

        # Teste com prefixos conflitantes (/24 vs /25)
        gw1 = rand_ip()
        gw2 = rand_ip()
        rede.definir_tabela_encaminhamento([
            ('192.168.1.0/24', gw1),
            ('192.168.1.128/25', gw2),
        ])
        # IP no /24 mas não no /25
        dest = '192.168.1.64'
        datagrama = b'E\x00\x00\x14\x00\x00\x00\x00@\x06\x00\x00\x01\x02\x03\x04' + str2addr(dest)
        enlace.callback(datagrama[:-10] + struct.pack('!H', calc_checksum(datagrama)) + datagrama[-8:])
        self.assertEqual(len(enlace.fila), 1)
        _, next_hop = enlace.fila.pop()
        self.assertEqual(next_hop, gw1, msg=f'IP {dest} deve ir para gw1 (/24)')
        # IP no /25
        dest = '192.168.1.129'
        datagrama = b'E\x00\x00\x14\x00\x00\x00\x00@\x06\x00\x00\x01\x02\x03\x04' + str2addr(dest)
        enlace.callback(datagrama[:-10] + struct.pack('!H', calc_checksum(datagrama)) + datagrama[-8:])
        self.assertEqual(len(enlace.fila), 1)
        _, next_hop = enlace.fila.pop()
        self.assertEqual(next_hop, gw2, msg=f'IP {dest} deve ir para gw2 (/25)')
