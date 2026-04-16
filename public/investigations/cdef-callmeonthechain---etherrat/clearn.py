import re
import os

# Вкажіть ім'я вашого файлу
FILE_NAME = "index.md"

def convert_ip_backticks_to_italics(filename):
    if not os.path.exists(filename):
        print(f"❌ Помилка: Файл '{filename}' не знайдено.")
        return

    # Регулярний вираз для пошуку саме IP-адрес у бектиках:
    # `                            - відкриваючий бектик
    # (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - 4 групи цифр (по 1-3), розділені крапками (зберігається у групу 1)
    # `                            - закриваючий бектик
    pattern = re.compile(r'`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`')

    try:
        with open(filename, 'r', encoding='utf-8') as file:
            content = file.read()

        # Виконуємо заміну: підставляємо знайдену IP-адресу (\1) між зірочками
        new_content = pattern.sub(r'*\1*', content)

        with open(filename, 'w', encoding='utf-8') as file:
            file.write(new_content)

        print(f"✅ Успішно! Усі `IP-адреси` замінено на *IP-адреси* у файлі '{filename}'.")

    except Exception as e:
        print(f"❌ Помилка: {e}")

if __name__ == "__main__":
    convert_ip_backticks_to_italics(FILE_NAME)