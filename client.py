# client.py
import socket
import ssl
import threading
import webbrowser
from cryptography.fernet import Fernet

HOST = "127.0.0.1"
PORT = 2711
CERT_FILE = "./server.crt"  # Chứng chỉ CA dùng để xác thực server

with open("./secret.key", "rb") as f:
    Fcipher = Fernet(f.read())


# Hàm nhận tin nhắn liên tục từ server (dùng thread riêng)
def receive_messages(ssl_client):
    print("Ban da vao phong chat, go 'exit' de thoat!")
    while True:
        try:
            message = ssl_client.recv(1024)
            decrypt_mess = Fcipher.decrypt(message)
            if not message:
                break
            print(decrypt_mess.decode(), flush=True)
        except:
            break


def connect_to_server():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(CERT_FILE)
    ssl_client = context.wrap_socket(client, server_hostname=HOST)
    ssl_client.connect((HOST, PORT))
    try:
        while True:
            menu = ssl_client.recv(1024).decode()
            if not menu:
                break
            print(menu, end="")
            choice = input()
            ssl_client.send(choice.encode())
            if choice == "1":  # Đăng nhập
                attempts = 3
                while attempts > 0:
                    prompt_username = ssl_client.recv(1024).decode()
                    print(prompt_username, end="")
                    username = input()
                    ssl_client.send(username.encode())
                    prompt_password = ssl_client.recv(1024).decode()
                    print(prompt_password, end="")
                    password = input()
                    ssl_client.send(password.encode())
                    response = ssl_client.recv(1024).decode()
                    print(f"Server: {response}")
                    if "Đăng nhập thành công" in response:
                        prompt_otp = ssl_client.recv(1024).decode()
                        print(prompt_otp, end="")
                        otp_code = input()
                        ssl_client.send(otp_code.encode())
                        otp_response = ssl_client.recv(1024).decode()
                        print(f"Server: {otp_response}")
                        if "Xác thực OTP thành công" in otp_response:
                            threading.Thread(
                                target=receive_messages, args=(ssl_client,), daemon=True
                            ).start()
                            while True:
                                message = input()
                                encrypted_mess = Fcipher.encrypt(message.encode())
                                ssl_client.send(encrypted_mess)
                                if message.lower() == "exit":
                                    break
                            break  # Thoát vòng login sau khi chat xong
                        else:
                            print("OTP không hợp lệ. Vui lòng thử lại.")
                            attempts -= 1
                    elif "Hết số lần thử" in response:
                        print("Bạn đã hết số lần thử, kết nối bị ngắt.")
                        break
                    else:
                        attempts -= 1
            elif choice == "2":  # Đăng ký
                while True:
                    prompt_new_username = ssl_client.recv(1024).decode()
                    print(prompt_new_username, end="")
                    username = input()
                    ssl_client.send(username.encode())
                    response = ssl_client.recv(1024).decode()
                    print(f"Server: {response}")
                    if "Username đã tồn tại" in response:
                        continue
                    prompt_password = ssl_client.recv(1024).decode()
                    print(prompt_password, end="")
                    password = input()
                    ssl_client.send(password.encode())
                    prompt_confirm = ssl_client.recv(1024).decode()
                    print(prompt_confirm, end="")
                    confirm_password = input()
                    ssl_client.send(confirm_password.encode())
                    response = ssl_client.recv(1024).decode()
                    print(f"Server: {response}")
                    if "Đăng ký thành công" in response:
                        if "Quét mã QR tại:" in response:
                            parts = response.split("Quét mã QR tại:")
                            if len(parts) > 1:
                                qr_url = parts[1].strip().split()[0]
                                print("Mở trình duyệt để hiển thị mã QR...")
                                webbrowser.open(qr_url)
                        break  # Kết thúc đăng ký, quay lại menu
            elif choice == "3":
                print("Thoát phiên làm việc.")
                break
            else:
                continue
    except Exception as e:
        print("Lỗi kết nối:", e)
    finally:
        ssl_client.close()


if __name__ == "__main__":
    connect_to_server()
