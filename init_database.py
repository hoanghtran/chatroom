import sqlite3

# Kết nối đến database (nếu chưa có sẽ được tạo mới)
conn = sqlite3.connect("Test.db")
cursor = conn.cursor()

# Xóa bảng Client nếu nó đã tồn tại
cursor.execute("DROP TABLE IF EXISTS Client;")

# Tạo bảng Client với các cột: Username, Password, Salt và otp_secret
cursor.execute("""
CREATE TABLE Client (
    Username TEXT PRIMARY KEY,
    Password TEXT,
    Salt TEXT,
    otp_secret TEXT
);
""")
conn.commit()
conn.close()

print("Database đã được khởi tạo lại thành công!")
