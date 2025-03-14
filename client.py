import socket
import ssl
import threading
from cryptography.fernet import Fernet
import time

HOST = "127.0.0.1"
PORT = 25219
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
            print(decrypt_mess.decode(), flush= True)  # In tin nhắn mà không thêm newline
        except:
            break

def connect_to_server():
    # Tạo socket TCP
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Tạo SSL context để xác thực chứng chỉ server
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(CERT_FILE)  # Load chứng chỉ để xác thực server

    # Kết nối an toàn đến server
    ssl_client = context.wrap_socket(client, server_hostname=HOST)
    ssl_client.connect((HOST, PORT))

    try:
        while True:
            # Nhận menu từ server
            menu = ssl_client.recv(1024).decode()
            if not menu:
                break
            print(menu, end="")

            # Nhập lựa chọn của người dùng
            choice = input()
            ssl_client.send(choice.encode())

            if choice == "1":  # Đăng nhập
                attempts = 3
                while attempts > 0:
                    # Nhận prompt nhập username
                    prompt_username = ssl_client.recv(1024).decode()
                    print(prompt_username, end="")
                    username = input()
                    ssl_client.send(username.encode())

                    # Nhận prompt nhập password
                    prompt_password = ssl_client.recv(1024).decode()
                    print(prompt_password, end="")
                    password = input()
                    ssl_client.send(password.encode())

                    # Nhận thông báo từ server sau kiểm tra username/password
                    response = ssl_client.recv(1024).decode()
                    print(f"Server2: {response}")

                    if "Đăng nhập thành công" in response:
                        # Sau khi username/password hợp lệ, nhận prompt OTP
                        prompt_otp = ssl_client.recv(1024).decode()
                        print(prompt_otp, end="")
                        otp_code = input()
                        ssl_client.send(otp_code.encode())

                        # Nhận kết quả xác thực OTP từ server
                        otp_response = ssl_client.recv(1024).decode()
                        print(f"Server1: {otp_response}")

                        if "Xác thực OTP thành công" in otp_response:
                            # Nếu OTP hợp lệ, bắt đầu nhận tin nhắn và chat
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
                        elif "Hết số lần thử" in otp_response:
                            print("Bạn đã hết số lần thử, kết nối bị ngắt, thử lại sau 30 giây.")
                            time.sleep(10)
                            break
                        else:
                            print("OTP không hợp lệ. Vui lòng thử lại.")
                            attempts -= 1

                    elif "Hết số lần thử" in response:
                        print("Bạn đã hết số lần thử, kết nối bị ngắt, thử lại sau 30 giây.")
                        time.sleep(10)
                        break
                    else:
                        attempts -= 1

            elif choice == "2":  # Đăng ký
                while True:
                    # Nhận prompt nhập username mới
                    prompt_new_username = ssl_client.recv(1024).decode()
                    print(prompt_new_username, end="")
                    username = input()
                    ssl_client.send(username.encode())

                    response = ssl_client.recv(1024).decode()
                    print(f"Server: {response}")
                    if "Username đã tồn tại" in response:
                        continue  # Nhập lại username nếu đã tồn tại

                    # Nhận prompt nhập mật khẩu
                    prompt_password = ssl_client.recv(1024).decode()
                    print(prompt_password, end="")
                    password = input()
                    ssl_client.send(password.encode())

                    # Nhận prompt xác nhận mật khẩu
                    prompt_confirm = ssl_client.recv(1024).decode()
                    print(prompt_confirm, end="")
                    confirm_password = input()
                    ssl_client.send(confirm_password.encode())

                    response = ssl_client.recv(1024).decode()
                    print(f"Server: {response}")
                    if "Đăng ký thành công" in response:
                        break  # Kết thúc đăng ký, quay lại menu
                    else:
                        continue
            elif choice == "3":
                print("Thoát phiên làm việc.")
                break
            else:
                # Nếu lựa chọn không hợp lệ, server sẽ thông báo và quay lại menu
                print(ssl_client.recv(1024).decode())
                continue

    except Exception as e:
        print("Lỗi kết nối:", e)
    finally:
        ssl_client.close()

if __name__ == "__main__":
    connect_to_server()
