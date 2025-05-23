# server.py
import hashlib
import sqlite3
import random
import socket
import ssl
import threading
import pyotp  # Thư viện hỗ trợ OTP

HOST = "127.0.0.1"
PORT = 2711
CERT_FILE = "./server.crt"
KEY_FILE = "./server.key"

clients = []  # Danh sách các kết nối client


# Kết nối đến SQLite Database
def connect_db():
    conn = sqlite3.connect("./Test.db")
    cursor = conn.cursor()
    return conn, cursor


# Hàm ghi log tin nhắn ra terminal
def log_message(message):
    print(message)


# Hàm xác thực đăng nhập (so sánh username và password đã băm)
def authenticate(username, password):
    conn, cursor = connect_db()
    cursor.execute("SELECT Salt FROM Client WHERE Username=?", (username,))
    result = cursor.fetchone()
    if result is None:
        conn.close()
        return False  # Username không tồn tại
    salt = result[0]
    realhash = hashlib.sha256((salt + password).encode()).hexdigest()
    cursor.execute(
        "SELECT * FROM Client WHERE Username=? AND Password=?", (username, realhash)
    )
    result = cursor.fetchone()
    conn.close()
    return result is not None


# Kiểm tra xem Username đã tồn tại hay chưa
def username_exists(username):
    conn, cursor = connect_db()
    cursor.execute("SELECT * FROM Client WHERE Username=?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result is not None


# Hàm đăng ký user, lưu thêm otp_secret vào database
def register_user(username, password, salt, otp_secret):
    conn, cursor = connect_db()
    cursor.execute(
        "INSERT INTO Client (Username, Password, Salt, Otp_secret) VALUES (?, ?, ?, ?)",
        (username, password, salt, otp_secret),
    )
    conn.commit()
    conn.close()


# Lấy otp_secret từ database theo username
def get_otp_secret(username):
    conn, cursor = connect_db()
    cursor.execute("SELECT Otp_secret FROM Client WHERE Username=?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result[0]
    return None


# Xử lý chat room: nhận và phát tin nhắn cho các client
def handle_chat(ssl_client, username):
    while True:
        try:
            encrypted_message = ssl_client.recv(1024)
            if not encrypted_message:
                break
            log_message(f"{username}:{encrypted_message.decode()}")
            broadcast(encrypted_message, ssl_client)
        except Exception as e:
            print("Lỗi trong handle_chat:", e)
            if ssl_client in clients:
                clients.remove(ssl_client)
            break


# Phát tin nhắn đến tất cả client trong chat room (trừ người gửi)
def broadcast(message, sender):
    for client in clients:
        if client != sender:
            try:
                client.send(message)
            except:
                if client in clients:
                    clients.remove(client)


# Xử lý đăng nhập với xác thực 2 bước OTP
def handle_login(ssl_client):
    attempts = 3
    while attempts > 0:
        ssl_client.send("Nhập Username: ".encode())
        username = ssl_client.recv(1024).decode().strip()
        ssl_client.send("Nhập Password: ".encode())
        password = ssl_client.recv(1024).decode().strip()
        if authenticate(username, password):
            ssl_client.send("Đăng nhập thành công! \n".encode())
            ssl_client.send("Nhập mã OTP từ app Microsoft Authenticator: ".encode())
            otp_input = ssl_client.recv(1024).decode().strip()
            otp_secret = get_otp_secret(username)
            totp = pyotp.TOTP(otp_secret)
            if totp.verify(otp_input):
                ssl_client.send(
                    "Xác thực OTP thành công! Bạn sẽ vào chat room.\n".encode()
                )
                clients.append(ssl_client)
                handle_chat(ssl_client, username)
                return True  # Đăng nhập thành công
            else:
                ssl_client.send("Xác thực OTP thất bại!\n".encode())
                attempts = -1
                continue
        else:
            attempts -= 1
            if attempts > 0:
                ssl_client.send(
                    f"Đăng nhập thất bại! Bạn còn {attempts} lần thử.\n".encode()
                )
            else:
                ssl_client.send("Đăng nhập thất bại! Hết số lần thử.\n".encode())
                return False
    return False


# Xử lý đăng ký tài khoản, bao gồm sinh OTP secret cho user và hiển thị QR code
def handle_register(ssl_client):
    while True:
        ssl_client.send("Hãy nhập username mới: ".encode())
        username = ssl_client.recv(1024).decode().strip()
        if username_exists(username):
            ssl_client.send("Username đã tồn tại. Hãy thử lại.\n".encode())
            continue
        else:
            ssl_client.send("Username hợp lệ.\n".encode())
        ssl_client.send("Hãy nhập mật khẩu: ".encode())
        password = ssl_client.recv(1024).decode().strip()
        ssl_client.send("Hãy nhập lại mật khẩu: ".encode())
        confirm_password = ssl_client.recv(1024).decode().strip()
        if password != confirm_password:
            ssl_client.send(
                "Xác nhận mật khẩu phải giống nhau. Hãy thử lại từ đầu.\n".encode()
            )
            continue
        salt = str(random.randint(100000, 999999))
        passhash = hashlib.sha256((salt + password).encode()).hexdigest()
        otp_secret = pyotp.random_base32()  # Sinh OTP secret cho user
        register_user(username, passhash, salt, otp_secret)
        totp = pyotp.TOTP(otp_secret)
        otp_uri = totp.provisioning_uri(name=username, issuer_name="ChatRoomApp")
        qr_url = (
            "https://api.qrserver.com/v1/create-qr-code/?data="
            + otp_uri
            + "&size=200x200"
        )
        ssl_client.send(
            f"Đăng ký thành công! OTP Secret của bạn: {otp_secret}\nQuét mã QR tại: {qr_url}\n".encode()
        )
        break


# Vòng lặp phiên làm việc của client (điều phối đăng nhập, đăng ký hoặc thoát)
def client_session(ssl_client):
    try:
        while True:
            menu = (
                "Chọn một tùy chọn:\n"
                "1. Đăng nhập\n"
                "2. Đăng ký\n"
                "3. Thoát\n"
                "Nhập lựa chọn: "
            )
            ssl_client.send(menu.encode())
            choice = ssl_client.recv(1024).decode().strip()
            if choice == "1":
                if handle_login(ssl_client):
                    break
            elif choice == "2":
                handle_register(ssl_client)
            elif choice == "3":
                ssl_client.send("Thoát.\n".encode())
                break
            else:
                ssl_client.send("Lựa chọn không hợp lệ.\n".encode())
    except ConnectionResetError:
        print("[*] Client đóng kết nối đột ngột!")
    finally:
        ssl_client.close()


# Khởi động Server với SSL
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"[*] Server đang lắng nghe trên {HOST}:{PORT}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        while True:
            client, addr = server.accept()
            ssl_client = context.wrap_socket(client, server_side=True)
            print(f"[*] Kết nối bảo mật từ {addr[0]}:{addr[1]}")
            threading.Thread(target=client_session, args=(ssl_client,)).start()


if __name__ == "__main__":
    start_server()
