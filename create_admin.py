import getpass
from main import db, hash_pw, init_db

init_db()
name = input("Full name: ")
username = input("Admin username: ")
password = getpass.getpass("Password: ")
c = db()
c.execute("INSERT INTO users(full_name, staff_id, username, password_hash, role, must_change) "
          "VALUES(?,?,?,?, 'admin', 0)", (name, "ADMIN-" + username, username, hash_pw(password)))
c.commit()
print("Admin created.")
