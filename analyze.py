import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from pathlib import Path
from datetime import datetime

# Путь к файлу
pcap_file = "dhcp.pcapng"

if not Path(pcap_file).is_file():
    print(f"Файл {pcap_file} не найден.")
    exit(1)

print(f"Анализируем дамп: {pcap_file}\n")

try:
    cap = pyshark.FileCapture(pcap_file, only_summaries=False, use_json=True)
except Exception as e:
    print(f"Ошибка открытия дампа: {e}")
    exit(1)

dhcp_messages = []
all_ips = set()
dns_queries = []

print("Обработка пакетов...")

for pkt in cap:
    try:
        # IP-адреса
        if 'IP' in pkt:
            all_ips.add(pkt.ip.src)
            all_ips.add(pkt.ip.dst)

        # DNS (редко, но проверяем)
        if 'DNS' in pkt:
            if hasattr(pkt.dns, 'qry_name'):
                dns_queries.append(pkt.dns.qry_name)

        # DHCP / BOOTP
        dhcp_layer = None
        if 'DHCP' in pkt:
            dhcp_layer = pkt.dhcp
        elif 'BOOTP' in pkt:
            dhcp_layer = pkt.bootp

        if dhcp_layer:
            msg = {
                'time': pkt.sniff_timestamp,
                'src': pkt.ip.src if 'IP' in pkt else 'unknown',
                'dst': pkt.ip.dst if 'IP' in pkt else 'unknown',
                'bootp_op': 'Boot Request (1)' if hasattr(dhcp_layer, 'op') and dhcp_layer.op == '1' else 'Boot Reply (2)' if hasattr(dhcp_layer, 'op') and dhcp_layer.op == '2' else 'Unknown',
                'dhcp_type': 'Unknown',
                'ciaddr': getattr(dhcp_layer, 'ciaddr', ''),
                'yiaddr': getattr(dhcp_layer, 'yiaddr', ''),
                'siaddr': getattr(dhcp_layer, 'siaddr', ''),
                'giaddr': getattr(dhcp_layer, 'giaddr', ''),
                'chaddr': getattr(dhcp_layer, 'chaddr', ''),
                'requested_ip': getattr(dhcp_layer, 'option_requested_ip_address', '')
            }

            # Тип по опции 53
            if hasattr(dhcp_layer, 'option_dhcp'):
                try:
                    opt53 = int(dhcp_layer.option_dhcp)
                    type_map = {
                        1: 'Discover 🟢',
                        2: 'Offer 🔵',
                        3: 'Request 🟡',
                        5: 'Ack 🟣',
                        7: 'Decline 🔴',
                        8: 'Nak 🔴'
                    }
                    msg['dhcp_type'] = type_map.get(opt53, f'Type {opt53}')
                except:
                    msg['dhcp_type'] = dhcp_layer.option_dhcp

            dhcp_messages.append(msg)

    except Exception as e:
        continue

cap.close()

# ------------------------------------------------------
# Красивый вывод
# ------------------------------------------------------
print(f"\n{'═' * 80}")
print("📊 АНАЛИЗ DHCP-ДАМПА")
print(f"{'═' * 80}")

print(f"Всего пакетов обработано: {len(dhcp_messages) + len(dns_queries)}")
print(f"DHCP-событий найдено: {len(dhcp_messages)}")
print(f"DNS-запросов: {len(dns_queries)}")
print(f"Уникальных IP-адресов: {len(all_ips)}")

if dns_queries:
    print("\n📡 DNS-запросы:")
    for q in dns_queries[:10]:
        print(f"  • {q}")
    if len(dns_queries) > 10:
        print(f"  ... и ещё {len(dns_queries) - 10}")
else:
    print("\n📡 DNS-запросов НЕТ (нормально для чистого DHCP-дампа)")

# ------------------------------------------------------
# Красивая таблица всех DHCP-событий
# ------------------------------------------------------
if dhcp_messages:
    df = pd.DataFrame(dhcp_messages)
    
    # Сортируем по времени
    df = df.sort_values('time')

    print(f"\n{'─' * 80}")
    print(f"📋 Все DHCP-события ({len(df)} шт.)")
    print(f"{'─' * 80}")

    # Цветная группировка по типу
    for _, row in df.iterrows():
        t = row['dhcp_type']
        color = {
            'Discover 🟢': '\033[92m',   # зелёный
            'Offer 🔵': '\033[94m',      # синий
            'Request 🟡': '\033[93m',    # жёлтый
            'Ack 🟣': '\033[95m',        # фиолетовый
            'Decline 🔴': '\033[91m',    # красный
            'Nak 🔴': '\033[91m',
            'Unknown': '\033[90m'        # серый
        }.get(t, '\033[0m')

        print(f"{color}{row['time'][:19]} | "
              f"{row['bootp_op']} → {t:<15} | "
              f"{row['src']} → {row['dst']} | "
              f"Client IP: {row['ciaddr']:<15} | "
              f"Your IP: {row['yiaddr']:<15} | "
              f"Requested: {row['requested_ip']:<15} | "
              f"MAC: {row['chaddr'][:17]}\033[0m")

    # Сохраняем в CSV
    df.to_csv('dhcp_all_events.csv', index=False)
    print(f"\nВсе события сохранены в dhcp_all_events.csv")

    # Статистика по типам
    type_counts = Counter(row['dhcp_type'] for row in dhcp_messages)
    print(f"\n{'─' * 80}")
    print("📊 Распределение типов сообщений")
    print(f"{'─' * 80}")
    for t, c in type_counts.most_common():
        print(f"  {t:20} : {c:3} шт.")

    # График
    plt.figure(figsize=(10, 6))
    types = list(type_counts.keys())
    counts = list(type_counts.values())
    colors = ['#4CAF50', '#2196F3', '#FFEB3B', '#9C27B0', '#F44336', '#F44336', '#9E9E9E']
    plt.bar(types, counts, color=colors[:len(types)], edgecolor='black')
    plt.title('Распределение типов DHCP-сообщений', fontsize=14, pad=15)
    plt.xlabel('Тип сообщения')
    plt.ylabel('Количество')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(rotation=45, ha='right')

    for i, v in enumerate(counts):
        plt.text(i, v + 0.2, str(v), ha='center', fontweight='bold')

    plt.tight_layout()
    plt.show()

else:
    print("\nDHCP-событий НЕ найдено. Возможно:")
    print("• В дампе нет BOOTP/DHCP-пакетов")
    print("• pyshark не распознал слой")
    print("Рекомендация: откройте дамп в Wireshark → фильтр 'bootp' или 'dhcp'")