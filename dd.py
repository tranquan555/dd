import socket
import threading
import time

# Hàm gửi gói tin
def send_packet(server_ip, server_port, packet, packet_count, thread_id, stop_event, max_retries=3):
    try:
        retries = 0
        while retries < max_retries:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(10)  # Timeout để tránh treo kết nối
                    s.connect((server_ip, server_port))
                    for i in range(packet_count):
                        if stop_event.is_set():  # Kiểm tra nếu sự kiện dừng được kích hoạt
                            print(f"[Thread-{thread_id}] Đã dừng do yêu cầu.")
                            return
                        s.sendall(packet)
                    print(f"[Thread-{thread_id}] Đã gửi thành công {packet_count} gói tin.")
                break  # Nếu thành công, thoát vòng lặp retry
            except (socket.timeout, ConnectionError) as e:
                retries += 1
                print(f"[Thread-{thread_id}] Thử lại lần {retries}/{max_retries} do lỗi: {e}")
                time.sleep(1)  # Đợi trước khi thử lại
        else:
            print(f"[Thread-{thread_id}] Thất bại sau {max_retries} lần thử.")
    except Exception as e:
        print(f"[Thread-{thread_id}] Gặp lỗi không xác định: {e}")  # Ghi lại lỗi để kiểm tra

# Hàm hủy luồng sau timeout
def stop_thread_after_timeout(stop_event, timeout=5):
    time.sleep(timeout)
    stop_event.set()
    print(f"[Thread Timeout] Luồng đã được yêu cầu dừng sau {timeout} giây.")

# Nhập IP và port từ người dùng
try:
    server_address = input("Nhập địa chỉ server (ví dụ: dragonsmp.myftp.org:15571): ")
    server_ip, server_port = server_address.split(":")
    server_port = int(server_port)  # Chuyển cổng sang số nguyên
except ValueError:
    print("Địa chỉ server không hợp lệ. Vui lòng nhập lại!")
    exit()

# Cho phép người dùng nhập nội dung gói tin
packet_input = input("Nhập nội dung gói tin (để trống để sử dụng gói tin mặc định 1MB): ").strip()
if packet_input:
    packet = packet_input.encode('utf-8')  # Chuyển nội dung gói tin sang byte
else:
    packet = b"\x00" * (1024 * 1024)  # Một gói tin mặc định 1MB

# Mỗi luồng gửi 10 gói tin
packet_count = 10

# Số luồng muốn sử dụng
try:
    thread_count = int(input("Nhập số lượng luồng: "))
    if thread_count <= 0:
        print("Số lượng luồng phải lớn hơn 0!")
        exit()
except ValueError:
    print("Số lượng luồng không hợp lệ. Vui lòng nhập lại!")
    exit()

# Tạo và khởi tạo các luồng
threads = []
stop_events = []  # Danh sách các sự kiện dừng

for i in range(thread_count):
    stop_event = threading.Event()
    stop_events.append(stop_event)
    
    thread = threading.Thread(target=send_packet, args=(server_ip, server_port, packet, packet_count, i + 1, stop_event))
    threads.append(thread)
    thread.start()

    # Cài đặt thời gian giới hạn 5 giây cho mỗi luồng
    timer = threading.Thread(target=stop_thread_after_timeout, args=(stop_event,))
    timer.start()

# Đợi tất cả các luồng hoàn thành
for thread in threads:
    thread.join()

print("[Hoàn tất] Đã hoàn tất việc gửi gói tin.")