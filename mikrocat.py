import json
import time
import os
import sys
import logging
from datetime import datetime
from librouteros import connect

#config
MIKROTIK_IP = "192.168.9.10"
USERNAME = "" #winbox_username
PASSWORD = "" #winbox_password
# address_lists - исправлены опечатки
ADDRESS_LIST_POOR_REP = "suricata_poor_reputation"
ADDRESS_LIST_SCAN = "suricata_port_scan"
ADDRESS_LIST_EXPLOIT = "suricata_exploit"

TEST_TIMEOUT = 60
POOR_REPUTATION_SIDS = list(range(2403300, 2403599))
SYN_SCAN_SIDS = [3400001, 3400002]
SYN_ACK_SCAN_SIDS = [3400003]
ACK_SCAN_SIDS = [3400004]
XMAS_SCAN_SIDS = [3400005]
FRAGMENTED_SCAN_SIDS = [3400006]
UDP_SCAN_SIDS = [3400007, 3400008]
EXPLOIT_SIDS = [3400020, 3400021]
ALL_SCAN_SIDS = (SYN_SCAN_SIDS + SYN_ACK_SCAN_SIDS + 
                 ACK_SCAN_SIDS + XMAS_SCAN_SIDS + 
                 FRAGMENTED_SCAN_SIDS + UDP_SCAN_SIDS)

EVE_FILE = "/var/log/suricata/eve.json"
STATE_FILE = "/var/lib/suricata/ip_blocker.state"
LOG_FILE = "/var/log/suricata/ip_blocker.log"

CHECK_INTERVAL = 30

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# mikrotik
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
                timeout=30,
                encoding='utf-8'
            )
            logger.info("MikroTik подключен")
            return True
        except Exception as e:
            logger.error(f"Ошибка подключения: {e}")
            return False

    def ensure_connection(self):
        if self.api is None:
            return self.connect()
        return True

    def ensure_address_lists(self):
        try:
            if not self.ensure_connection():
                return False
          
            address_list = self.api.path('/ip/firewall/address-list')

            lists_to_check = [
                ADDRESS_LIST_POOR_REP,
                ADDRESS_LIST_SCAN,
                ADDRESS_LIST_EXPLOIT
            ]
            
            for list_name in lists_to_check:
                test_ip = "200.91.236.125"
                comment = f"Test entry"
                
                try:
                    address_list.add(
                        list=list_name,
                        address=test_ip,
                        comment=comment,
                        timeout=TEST_TIMEOUT
                    )
                    logger.info(f"Создан список '{list_name}'")
                    time.sleep(1)
                    
                except Exception as e:
                    if "already have" in str(e).lower():
                        logger.info(f"Список '{list_name}' уже существует")
                    else:
                        logger.warning(f"Предупреждение для списка '{list_name}': {e}")

            return True
        except Exception as e:
            logger.error(f"Ошибка создания списков: {e}")
            return False

    def add_ip(self, ip, list_type, dest_ip="N/A", sid="", scan_type=""):
        try:
            # определяем в какой список добавить
            if list_type == "poor_rep":
                list_name = ADDRESS_LIST_POOR_REP
                comment = f"Poor Reputation IP - SID:{sid}"
            elif list_type == "scan":
                list_name = ADDRESS_LIST_SCAN
                comment = f"Port Scan - {scan_type} - SID:{sid}"
            elif list_type == "exploit":
                list_name = ADDRESS_LIST_EXPLOIT
                comment = f"Possible Exploit/Shell - SID:{sid}"
            else:
                logger.error(f"Неизвестный тип списка: {list_type}")
                return False

            if dest_ip != "N/A":
                comment += f" - Target:{dest_ip}"
            
            comment += f" - {datetime.now().strftime('%Y-%m-%d %H:%M')}"

            address_list = self.api.path('/ip/firewall/address-list')
            
            address_list.add(
                list=list_name,
                address=ip,
                comment=comment
            )

            logger.info(f"Добавлен {ip} в список '{list_name}' навсегда (SID:{sid})")
            return True

        except Exception as e:
            error_msg = str(e)
            if "already have such entry" in error_msg.lower():
                logger.debug(f"IP {ip} уже в списке '{list_name}'")
                return True
            else:
                logger.error(f"Ошибка добавления {ip} в '{list_name}': {error_msg}")
                return False

    def get_blocked_counts(self):
        counts = {
            'poor_rep': 0,
            'scan': 0,
            'exploit': 0
        }
        try:
            if not self.ensure_connection():
                return counts

            address_list = self.api.path('/ip/firewall/address-list')
            
            for item in address_list:
                list_name = item.get('list', '')
                if list_name == ADDRESS_LIST_POOR_REP:
                    counts['poor_rep'] += 1
                elif list_name == ADDRESS_LIST_SCAN:
                    counts['scan'] += 1
                elif list_name == ADDRESS_LIST_EXPLOIT:
                    counts['exploit'] += 1

        except Exception as e:
            logger.warning(f"Не удалось получить статистику: {str(e)[:100]}")
            
        return counts

    def get_blocked_ips(self):
        """Старый метод для обратной совместимости"""
        counts = self.get_blocked_counts()
        total = sum(counts.values())
        return [{}] * total

# suricata
def is_external_ip(ip):
    # проверка, что ip внешний
    if not ip:
        return False

    # локальные диапазоны
    local_prefixes = [
        '192.168.',
        '10.',
        '127.',
        '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.',
        '172.24.', '172.25.', '172.26.', '172.27.',
        '172.28.', '172.29.', '172.30.', '172.31.',
        '169.254.',
        '224.', '225.', '226.', '227.', '228.', '229.', '230.', '231.', '232.', '233.', '234.', '235.', '236.', '237.', '238.', '239.',
        '255.255.255.255',
    ]

    for prefix in local_prefixes:
        if ip.startswith(prefix):
            return False

    return True

def read_last_position(state_file):
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                return int(f.read().strip())
        except:
            return 0
    return 0

def save_position(position, state_file):
    try:
        os.makedirs(os.path.dirname(state_file), exist_ok=True)
        with open(state_file, 'w') as f:
            f.write(str(position))
    except Exception as e:
        logger.error(f"Ошибка сохранения позиции: {e}")

def find_eve_file():
    """Найти файл eve.json"""
    alt_paths = [
        "/var/log/suricata/eve.json",
        "/root/NDR/config/containers-data/suricata/logs/eve.json",
        "/opt/suricata/logs/eve.json",
        "/var/lib/suricata/logs/eve.json",
        "/tmp/suricata/eve.json"
    ]

    if os.path.exists(EVE_FILE):
        return EVE_FILE

    for path in alt_paths:
        if os.path.exists(path):
            logger.info(f"Найден альтернативный путь к логам: {path}")
            return path

    return EVE_FILE

def determine_alert_type(sid):
    """Определить тип алерта по SID"""
    if sid in POOR_REPUTATION_SIDS:
        return "poor_rep", "Poor Reputation"
    elif sid in SYN_SCAN_SIDS:
        return "scan", "SYN Scan"
    elif sid in SYN_ACK_SCAN_SIDS:
        return "scan", "SYN-ACK Scan"
    elif sid in ACK_SCAN_SIDS:
        return "scan", "ACK Scan"
    elif sid in XMAS_SCAN_SIDS:
        return "scan", "XMAS Scan"
    elif sid in FRAGMENTED_SCAN_SIDS:
        return "scan", "Fragmented Scan"
    elif sid in UDP_SCAN_SIDS:
        return "scan", "UDP Scan"
    elif sid in EXPLOIT_SIDS:
        return "exploit", "Possible Exploit/Shell"
    else:
        return None, None

def process_alerts(mikrotik, eve_file, state_file):
    try:
        if not os.path.exists(eve_file):
            logger.warning(f"Файл {eve_file} не найден")
            return 0

        last_pos = read_last_position(state_file)
        current_size = os.path.getsize(eve_file)

        if current_size < last_pos:
            last_pos = 0

        if current_size <= last_pos:
            return 0

        logger.debug(f"Чтение лога с позиции {last_pos} до {current_size}")

        processed_count = 0
        found_alerts = []  # (ip, dest_ip, sid, list_type, alert_type)

        with open(eve_file, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(last_pos)

            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)

                    if event.get('event_type') == 'alert':
                        alert = event.get('alert', {})
                        sid = alert.get('signature_id')
                        src_ip = event.get('src_ip')
                        dest_ip = event.get('dest_ip', 'N/A')
                        
                        if sid and src_ip and is_external_ip(src_ip):
                            list_type, alert_type = determine_alert_type(sid)
                            
                            if list_type:
                                if (src_ip, dest_ip, sid, list_type, alert_type) not in found_alerts:
                                    found_alerts.append((src_ip, dest_ip, sid, list_type, alert_type))
                                    logger.info(f"Найдено: {src_ip} - {alert_type} (SID:{sid})")

                except json.JSONDecodeError as e:
                    logger.debug(f"Ошибка JSON в строке {line_num}: {e}")
                    continue
                except Exception as e:
                    logger.debug(f"Ошибка обработки строки {line_num}: {e}")
                    continue

        for src_ip, dest_ip, sid, list_type, alert_type in found_alerts:
            if mikrotik.add_ip(src_ip, list_type, dest_ip, sid, alert_type):
                processed_count += 1
                time.sleep(0.1)

        save_position(current_size, state_file)

        if processed_count > 0:
            logger.info(f"Добавлено {processed_count} новых IP в списки блокировки")

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
    print("🚀 SURICATA ADVANCED IP BLOCKER")
    print("="*60)
    print(f"MikroTik: {MIKROTIK_IP}")
    print(f"Списки блокировки (навсегда):")
    print(f"  • {ADDRESS_LIST_POOR_REP} - IP с плохой репутацией")
    print(f"  • {ADDRESS_LIST_SCAN} - Сканирование портов")
    print(f"  • {ADDRESS_LIST_EXPLOIT} - Возможные эксплойты")
    print("="*60)
    print(f"Отслеживаемые SID:")
    print(f"  • Poor Reputation: {len(POOR_REPUTATION_SIDS)} правил")
    print(f"  • Port Scanning: {len(ALL_SCAN_SIDS)} типов сканирования")
    print(f"  • Exploits: {len(EXPLOIT_SIDS)} правил")
    print("="*60)
    print(f"Лог файл: {LOG_FILE}")
    print("="*60 + "\n")

    logger.info("Инициализация MikroTik...")
    mikrotik = MikroTikManager()

    if not mikrotik.api:
        logger.error("Не удалось подключиться к MikroTik")
        sys.exit(1)

    logger.info("Проверка и создание списков адресов...")
    if not mikrotik.ensure_address_lists():
        logger.warning("Проблемы со списками, но продолжаем...")

    counts = mikrotik.get_blocked_counts()
    logger.info("Текущая статистика блокировок:")
    logger.info(f"  • {ADDRESS_LIST_POOR_REP}: {counts['poor_rep']} IP")
    logger.info(f"  • {ADDRESS_LIST_SCAN}: {counts['scan']} IP")
    logger.info(f"  • {ADDRESS_LIST_EXPLOIT}: {counts['exploit']} IP")
    total = sum(counts.values())
    logger.info(f"  Всего заблокировано: {total} IP")

    eve_file = find_eve_file()
    logger.info(f"Использую файл логов: {eve_file}")

    if not os.path.exists(eve_file):
        logger.error(f"Файл логов не найден: {eve_file}")
        logger.info("Проверьте что Suricata запущена и пишет логи")

    logger.info(f"Начинаю мониторинг файла: {eve_file}")
    logger.info(f"Интервал проверки: {CHECK_INTERVAL} секунд")
    logger.info("Для остановки нажмите Ctrl+C\n")

    status_counter = 0

    try:
        while True:
            try:
                processed = process_alerts(mikrotik, eve_file, STATE_FILE)

                status_counter += 1

                if status_counter % 20 == 0:
                    counts = mikrotik.get_blocked_counts()
                    logger.info("Статус блокировок:")
                    logger.info(f"  • {ADDRESS_LIST_POOR_REP}: {counts['poor_rep']} IP")
                    logger.info(f"  • {ADDRESS_LIST_SCAN}: {counts['scan']} IP")
                    logger.info(f"  • {ADDRESS_LIST_EXPLOIT}: {counts['exploit']} IP")
                    total = sum(counts.values())
                    logger.info(f"  Всего: {total} IP")

                    if not os.path.exists(eve_file):
                        logger.warning(f"Файл логов пропал: {eve_file}")
                        eve_file = find_eve_file() 
                        if os.path.exists(eve_file):
                            logger.info(f"Файл найден: {eve_file}")

                time.sleep(CHECK_INTERVAL)

            except KeyboardInterrupt:
                logger.info("\nОстановка по запросу пользователя")
                break
            except Exception as e:
                logger.error(f"Ошибка в основном цикле: {e}")
                time.sleep(60)

    finally:
        if mikrotik.api:
            try:
                mikrotik.api.close()
                logger.info("Соединение с MikroTik закрыто")
            except:
                pass

        logger.info("Программа завершена")

if __name__ == "__main__":
    main()