import json
import time
import os
import sys
import logging
from datetime import datetime
from librouteros import connect

# configuration
MIKROTIK_IP = "192.168.9.10"
USERNAME = "" # задавать только переменными окружения
PASSWORD = "" # задавать только переменными окружения
ADDRESS_LIST = "suricata_poor_reputation"
TIMEOUT = "12h"

# sids for rules
POOR_REPUTATION_SIDS = list(range(2403300, 2403599))

# files!
EVE_FILE = "/var/log/suricata/eve.json"
STATE_FILE = "/var/lib/suricata/poor_rep.state"
LOG_FILE = "/var/log/suricata/poor_rep_block.log"

# check_interval
CHECK_INTERVAL = 30

# mikrotik_functions
class MikroTikManager:
    def __init__(self):
        self.api = None
        self.connect()

    def connect(self):
        try:
            self.api = connect(
                username=USERNAME,
                password=PASSWORD,
                host=MIKROTIK_IP,
                port=8728,
                timeout=30
            )
            logger.info("MikroTik подключен")
            return True
        except Exception as e:
            logger.error(f"Ошибка подключения: {e}")
            return False

    def ensure_connection(self):
        """Убедиться что соединение активно"""
        if self.api is None:
            return self.connect()
        return True

    def ensure_address_list(self):
        """Простая проверка - пробуем добавить тестовый IP"""
        try:
            if not self.ensure_connection():
                return False

            comment = f"Test entry - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            address_list = self.api.path('/ip/firewall/address-list')

            # try to add adress
            try:
                address_list.add(
                    list=ADDRESS_LIST,
                    address="200.91.236.125",
                    comment=comment,
                    timeout=50
                )
                logger.info(f"Создан список '{ADDRESS_LIST}'")
            except Exception as e:
                if "already have" in str(e):
                    logger.info(f"Список '{ADDRESS_LIST}' уже существует")
                else:
                    raise e

            return True
        except Exception as e:
            logger.error(f"Ошибка работы со списком: {e}")
            return False

    def add_ip(self, ip, dest_ip="N/A", sid=""):
        """Добавить IP в список"""
        try:
            comment = f"Poor Reputation IP - SID:{sid} - Target:{dest_ip} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"

            address_list = self.api.path('/ip/firewall/address-list')
            address_list.add(
                list=ADDRESS_LIST,
                address=ip,
                comment=comment,
                timeout=43200
            )

            logger.info(f"Добавлен: {ip} (Dest_ip: {dest_ip}, SID:{sid})")
            return True

        except Exception as e:
            error_msg = str(e)
            if "already have such entry" in error_msg:
                logger.debug(f"IP {ip} уже в списке")
                return True
            else:
                logger.error(f"Ошибка добавления {ip}: {error_msg}")

                # Переподключение при ошибке
                if "connection" in error_msg.lower():
                    self.connect()
                return False

    def get_blocked_ips(self):
        """Получить список заблокированных IP"""
        try:
            if not self.ensure_connection():
                return []

            address_list = self.api.path('/ip/firewall/address-list')
            blocked = []

            for item in address_list:
                if item.get('list') == ADDRESS_LIST:
                    blocked.append({
                        'address': item.get('address'),
                        'comment': item.get('comment', '')
                    })

            return blocked
        except Exception as e:
            logger.error(f"Ошибка получения списка: {e}")
            return []

# suricata functions

def is_external_ip(ip):
    """Проверить что IP внешний (не локальный)"""
    if not ip:
        return False

    # Локальные диапазоны
    local_prefixes = [
        '192.168.',
        '10.',
        '127.',
        '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.',
        '172.24.', '172.25.', '172.26.', '172.27.',
        '172.28.', '172.29.', '172.30.', '172.31.',
        '169.254.',  # Link-local
        '224.', '225.', '226.', '227.', '228.', '229.', '230.', '231.', '232.', '233.', '234.', '235.', '236.', '237.', '238.', '239.',  # Multicast
        '255.255.255.255',  # Broadcast
    ]

    for prefix in local_prefixes:
        if ip.startswith(prefix):
            return False

    return True

def read_last_position(state_file):
    """Прочитать последнюю позицию в файле"""
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                return int(f.read().strip())
        except:
            return 0
    return 0

def save_position(position, state_file):
    """Сохранить позицию в файле"""
    try:
        os.makedirs(os.path.dirname(state_file), exist_ok=True)
        with open(state_file, 'w') as f:
            f.write(str(position))
    except Exception as e:
        logger.error(f"Ошибка сохранения позиции: {e}")

def find_eve_file():
    """Найти файл eve.json"""
    # Альтернативные пути для поиска
    alt_paths = [
        "/var/log/suricata/eve.json",
        "/root/NDR/config/containers-data/suricata/logs/eve.json",
        "/opt/suricata/logs/eve.json",
        "/var/lib/suricata/logs/eve.json",
        "/tmp/suricata/eve.json"
    ]

    # Проверяем основной путь
    if os.path.exists(EVE_FILE):
        return EVE_FILE

    # Ищем в альтернативных путях
    for path in alt_paths:
        if os.path.exists(path):
            logger.info(f"Найден альтернативный путь к логам: {path}")
            return path

    # Если не нашли, возвращаем основной (будет ошибка при попытке чтения)
    return EVE_FILE

def process_alerts(mikrotik, eve_file, state_file):
    """Обработать новые алерты"""
    try:
        if not os.path.exists(eve_file):
            logger.warning(f"Файл {eve_file} не найден")
            return 0

        last_pos = read_last_position(state_file)
        current_size = os.path.getsize(eve_file)

        # Если файл уменьшился (ротация логов)
        if current_size < last_pos:
            last_pos = 0

        if current_size <= last_pos:
            # Нет новых данных
            return 0

        logger.debug(f"Чтение лога с позиции {last_pos} до {current_size}")

        processed_count = 0
        found_ips = []  # Список для хранения найденных IP и SID

        with open(eve_file, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(last_pos)

            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)

                    # Проверяем что это alert
                    if event.get('event_type') == 'alert':
                        alert = event.get('alert', {})
                        sid = alert.get('signature_id')
                        src_ip = event.get('src_ip')
                        dest_ip = event.get('dest_ip', 'N/A')

                        # Проверяем Poor Reputation SID
                    dest_ip = event.get('dest_ip', 'N/A') #для комментария с dest.ip
                    if sid in POOR_REPUTATION_SIDS and src_ip:
                            # Проверяем что IP внешний
                            if is_external_ip(src_ip):
                                # Проверяем, нет ли уже этого IP в списке
                                if (src_ip, dest_ip, sid) not in found_ips:
                                    found_ips.append((src_ip, dest_ip, sid))
                                    logger.info(f"Найден Poor Reputation: {src_ip} (SID:{sid})")

                except json.JSONDecodeError as e:
                    logger.debug(f"Ошибка JSON в строке {line_num}: {e}")
                    continue
                except Exception as e:
                    logger.debug(f"Ошибка обработки строки {line_num}: {e}")
                    continue

        # Добавляем найденные IP в MikroTik
        for src_ip, dest_ip, sid in found_ips:
            if mikrotik.add_ip(src_ip, dest_ip, sid):
                processed_count += 1
                time.sleep(0.1)  # Пауза между запросами

        # Сохраняем новую позицию
        save_position(current_size, state_file)

        if processed_count > 0:
            logger.info(f"Добавлено {processed_count} новых IP")

        return processed_count

    except Exception as e:
        logger.error(f"Ошибка обработки алертов: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        return 0

# main

def main():
    """Основная функция"""
    print("\n" + "="*60)
    print(" SURICATA POOR REPUTATION IP BLOCKER")
    print("="*60)
    print(f"MikroTik: {MIKROTIK_IP}")
    print(f"Address List: {ADDRESS_LIST}")
    print(f"Правил Poor Reputation: {len(POOR_REPUTATION_SIDS)}")
    print(f"Лог файл: {LOG_FILE}")
    print("="*60 + "\n")

    # Инициализация MikroTik
    logger.info("Инициализация MikroTik...")
    mikrotik = MikroTikManager()

    if not mikrotik.api:
        logger.error("Не удалось подключиться к MikroTik")
        sys.exit(1)

    # Создание/проверка списка
    logger.info("Проверка address list...")
    if not mikrotik.ensure_address_list():
        logger.warning("Проблемы со списком, но продолжаем...")

    # Показываем текущие заблокированные IP
    blocked = mikrotik.get_blocked_ips()
    logger.info(f"Текущее количество заблокированных IP: {len(blocked)}")

    # Находим файл логов
    eve_file = find_eve_file()
    logger.info(f"Использую файл логов: {eve_file}")

    if not os.path.exists(eve_file):
        logger.error(f"Файл логов не найден: {eve_file}")
        logger.info("Проверьте что Suricata запущена и пишет логи")
        logger.info("Альтернативные пути проверены, файл не найден")
        # Не выходим, продолжаем в надежде что файл появится

    logger.info(f"Начинаю мониторинг файла: {eve_file}")
    logger.info(f"Интервал проверки: {CHECK_INTERVAL} секунд")
    logger.info("Для остановки нажмите Ctrl+C\n")

    # Счетчик для периодического вывода статуса
    status_counter = 0

    # Основной цикл
    try:
        while True:
            try:
                processed = process_alerts(mikrotik, eve_file, STATE_FILE)

                status_counter += 1

                # Периодически показываем статус
                if status_counter % 20 == 0:  # Каждые 20 циклов
                    blocked = mikrotik.get_blocked_ips()
                    logger.info(f"Статус: {len(blocked)} IP в списке блокировки")

                    # Проверяем что файл логов существует
                    if not os.path.exists(eve_file):
                        logger.warning(f"Файл логов пропал: {eve_file}")
                        eve_file = find_eve_file()  # Пробуем найти снова
                        if os.path.exists(eve_file):
                            logger.info(f"Файл найден: {eve_file}")

                time.sleep(CHECK_INTERVAL)

            except KeyboardInterrupt:
                logger.info("\nОстановка по запросу пользователя")
                break
            except Exception as e:
                logger.error(f"Ошибка в основном цикле: {e}")
                time.sleep(60)  # Пауза при ошибке

    finally:
        # Закрытие соединения
        if mikrotik.api:
            try:
                mikrotik.api.close()
                logger.info("Соединение с MikroTik закрыто")
            except:
                pass

        logger.info("Программа завершена")

if __name__ == "__main__":
    main()
