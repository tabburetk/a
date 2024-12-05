import hashlib
import datetime
import re  # Для перевірки спеціальних символів


from easypasswords import easy_passwords_list


# Система користувачів, де зберігаються ідентифікатори, паролі та рівні доступу
users_db = {
    "user1": {"password": "password1", "role": "user", "info": "Інформація користувача 1"},
    "user2": {"password": "password2", "role": "user", "info": "Інформація користувача 2"},
    "admin": {"password": "admin123", "role": "admin", "info": "Інформація адміністратора"},
    "moderator": {"password": "moderator123", "role": "moderator", "info": "Інформація модератора"}
}


# Система для журналу аудиту
audit_log = []
console_output = []  # Змінна для збереження всіх повідомлень


# Функція для хешування пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


#Функція для реєстрації нового користувача
def register_user(username):
    # Перевірка наявності користувача в базі даних
    if username in users_db:
        add_to_console(f"Користувач {username} вже існує.")
        return False


    # Блок введення пароля з перевірками
    while True:
        password = input("Введіть пароль: ").strip()


        # Перевірка мінімальної довжини пароля
        if len(password) < 8:
            add_to_console("Пароль занадто короткий, мінімальна довжина 8 символів.")
            continue


        # Перевірка на прості паролі
        if password in easy_passwords_list:
            add_to_console("Пароль надто простий. Використовуйте складніший пароль.")
            continue
           
        # Перевірка наявності спеціальних символів
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            add_to_console("Пароль повинен містити хоча б один спеціальний символ.")
            continue


        # Якщо пароль відповідає всім вимогам, зберігаємо користувача
        users_db[username] = {"password": hash_password(password), "role": "user", "info": "Нова особиста інформація"}
        log_audit(username, f"Зареєстровано нового користувача: {username}")
        add_to_console(f"Користувач {username} успішно зареєстрований.")
        return True


# Функція для входу в систему
def login_user(username, password):
    if username not in users_db:
        add_to_console("Невірний ідентифікатор користувача.")
        return None
    # Порівнюємо хеш пароля з бази даних і введеного пароля
    if users_db[username]["password"] != hash_password(password):
        add_to_console("Невірний пароль.")
        return None
    log_audit(username, f"Користувач {username} увійшов в систему.")
    add_to_console(f"Ласкаво просимо, {username}!")
    return username


# Функція для зміни рівня доступу користувача
def change_user_role(admin_username, target_username, new_role):
    if users_db[admin_username]["role"] != "admin":
        add_to_console("Тільки адміністратори можуть змінювати ролі.")
        return False
    if target_username not in users_db:
        add_to_console(f"Користувача {target_username} не знайдено.")
        return False
    if new_role not in ["admin", "moderator", "user"]:
        add_to_console("Невірний рівень доступу.")
        return False
    old_role = users_db[target_username]["role"]
    users_db[target_username]["role"] = new_role
    log_audit(admin_username, f"Змінив рівень доступу користувача {target_username} з {old_role} на {new_role}.")
    add_to_console(f"Рівень доступу користувача {target_username} змінено на {new_role}.")
    return True


# Функція для ведення журналу аудиту
def log_audit(user_id, action_description):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    audit_log.append(f"{timestamp} – {user_id}: {action_description}")


# Функція для перегляду журналу аудиту
def view_audit_log(username):
    if users_db[username]["role"] not in ["admin", "moderator"]:
        add_to_console("Тільки адміністратори та модератори можуть переглядати журнал аудиту.")
        return
    for entry in audit_log:
        add_to_console(entry)


# Функція для перегляду або зміни особистої інформації користувача
def view_or_edit_info(username):
    print("\nВаші дані:")
    print(f"Інформація: {users_db[username]['info']}")
    action = input("\n1. Змінити інформацію\n2. Повернутись\nВиберіть опцію: ").strip()
    if action == "1":
        new_info = input("Введіть нову інформацію: ").strip()
        users_db[username]["info"] = new_info
        log_audit(username, f"Користувач {username} змінив свою інформацію.")
        add_to_console(f"Інформація користувача {username} була оновлена.")
    elif action == "2":
        return


# Функція для виведення повідомлень на консоль
def add_to_console(message):
    console_output.append(message)
    print(message)


# Функція для показу доступних дій в залежності від ролі
def show_available_actions(role, username):
    if role == "admin":
        print("\nДоступні дії для адміністратора:")
        print("1. Перегляд журналу аудиту")
        print("2. Змінити рівень доступу користувача")
        print("3. Переглянути або змінити свою інформацію")
        print("4. Вихід")
    elif role == "moderator":
        print("\nДоступні дії для модератора:")
        print("1. Перегляд журналу аудиту")
        print("2. Переглянути або змінити свою інформацію")
        print("3. Вихід")
    elif role == "user":
        print("\nДоступні дії для користувача:")
        print("1. Переглянути або змінити свою інформацію")
        print("2. Вихід")


# Основне меню
def main_menu():
    while True:
        print("\nМеню:")
        print("1. Реєстрація нового користувача")
        print("2. Вхід в систему")
        print("3. Вихід")
        choice = input("Виберіть опцію: ").strip()


        if choice == "1":
            username = input("Введіть ім'я користувача: ").strip()
            register_user(username)


        elif choice == "2":
            username = input("Введіть ім'я користувача: ").strip()
            password = input("Введіть пароль: ").strip()
            logged_in_user = login_user(username, password)


            if logged_in_user:
                role = users_db[logged_in_user]["role"]
                show_available_actions(role, logged_in_user)


                while True:
                    action = input("\nВиберіть дію: ").strip()


                    if role == "admin":
                        if action == "1":
                            view_audit_log(logged_in_user)
                        elif action == "2":
                            target_username = input("Введіть ім'я користувача для зміни рівня доступу: ").strip()
                            new_role = input("Введіть новий рівень доступу (admin, moderator, user): ").strip()
                            change_user_role(logged_in_user, target_username, new_role)
                        elif action == "3":
                            view_or_edit_info(logged_in_user)
                        elif action == "4":
                            break
                        else:
                            add_to_console("Невірний вибір. Спробуйте ще раз.")
                    elif role == "moderator":
                        if action == "1":
                            view_audit_log(logged_in_user)
                        elif action == "2":
                            view_or_edit_info(logged_in_user)
                        elif action == "3":
                            break
                        else:
                            add_to_console("Невірний вибір. Спробуйте ще раз.")
                    elif role == "user":
                        if action == "1":
                            view_or_edit_info(logged_in_user)
                        elif action == "2":
                            break
                        else:
                            add_to_console("Невірний вибір. Спробуйте ще раз.")


        elif choice == "3":
            print("До побачення!")
            break
        else:
            add_to_console("Невірний вибір, спробуйте ще раз.")


# Запуск програми
if __name__ == "__main__":
    # Хешуємо паролі для існуючих користувачів (включаючи admin)
    for user, data in users_db.items():
        users_db[user]["password"] = hash_password(data["password"])


    main_menu()
