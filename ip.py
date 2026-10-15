from iputils import *
import struct


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []          # [(rede_int, tamanho_prefixo, next_hop)]
        self.identification = 0   # contador para o campo Identification

    # ------------------------------------------------------------------
    # Auxiliares
    # ------------------------------------------------------------------
    @staticmethod
    def _addr_to_int(addr):
        return int.from_bytes(str2addr(addr), 'big')

    def _montar_datagrama(self, payload, src_addr, dst_addr, proto, ttl=64):
        """Monta um datagrama IPv4 (sem opções) com checksum correto."""
        vihl = (4 << 4) | 5
        total_len = 20 + len(payload)
        ident = self.identification
        self.identification = (self.identification + 1) & 0xFFFF

        cabecalho = struct.pack('!BBHHHBBH', vihl, 0, total_len, ident,
                                0, ttl, proto, 0) \
            + str2addr(src_addr) + str2addr(dst_addr)
        checksum = calc_checksum(cabecalho)
        cabecalho = cabecalho[:10] + struct.pack('!H', checksum) + cabecalho[12:]
        return cabecalho + payload

    # ------------------------------------------------------------------
    # Recepção / roteamento
    # ------------------------------------------------------------------
    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            ttl -= 1
            if ttl <= 0:
                self._enviar_time_exceeded(datagrama, src_addr)
                return

            ihl = datagrama[0] & 0xf
            cabecalho = bytearray(datagrama[:4 * ihl])
            cabecalho[8] = ttl                  # novo TTL
            cabecalho[10:12] = b'\x00\x00'      # zera checksum
            cabecalho[10:12] = struct.pack('!H', calc_checksum(bytes(cabecalho)))
            novo = bytes(cabecalho) + datagrama[4 * ihl:]

            next_hop = self._next_hop(dst_addr)
            self.enlace.enviar(novo, next_hop)

    def _enviar_time_exceeded(self, datagrama_original, destino):
        """Envia ICMP Time Exceeded (tipo 11, código 0) ao remetente."""
        ihl = datagrama_original[0] & 0xf
        # cabeçalho IP original + 8 primeiros bytes do payload
        trecho = datagrama_original[:4 * ihl + 8]

        icmp = struct.pack('!BBHI', 11, 0, 0, 0) + trecho
        checksum = calc_checksum(icmp)
        icmp = icmp[:2] + struct.pack('!H', checksum) + icmp[4:]

        datagrama = self._montar_datagrama(icmp, self.meu_endereco,
                                           destino, IPPROTO_ICMP)
        next_hop = self._next_hop(destino)
        self.enlace.enviar(datagrama, next_hop)

    # ------------------------------------------------------------------
    # Tabela de encaminhamento
    # ------------------------------------------------------------------
    def _next_hop(self, dest_addr):
        dest = self._addr_to_int(dest_addr)
        # tabela já está ordenada do prefixo mais longo para o mais curto,
        # então a primeira entrada que casar é a de maior prefixo
        for rede, prefixo, next_hop in self.tabela:
            mascara = (0xFFFFFFFF << (32 - prefixo)) & 0xFFFFFFFF
            if (dest & mascara) == rede:
                return next_hop
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        nova = []
        for cidr, next_hop in tabela:
            endereco, n = cidr.split('/')
            n = int(n)
            mascara = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF
            rede = self._addr_to_int(endereco) & mascara
            nova.append((rede, n, next_hop))
        # prefixo mais longo primeiro (passo 3)
        nova.sort(key=lambda e: e[1], reverse=True)
        self.tabela = nova

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        datagrama = self._montar_datagrama(segmento, self.meu_endereco,
                                           dest_addr, IPPROTO_TCP)
        self.enlace.enviar(datagrama, next_hop)