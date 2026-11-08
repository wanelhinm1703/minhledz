#!/usr/bin/env python3
"""
Tiện ích đọc và tra cứu dữ liệu trong toolkit/data/kb.sqlite
Cách dùng:
  python3 scripts/read_db.py                     # Xem danh sách tất cả các bảng và số lượng dòng
  python3 scripts/read_db.py cve                 # Xem 5 dòng đầu của bảng cve
  python3 scripts/read_db.py cwe                 # Xem 5 dòng đầu của bảng cwe
  python3 scripts/read_db.py findings            # Xem các lỗ hổng đã phát hiện
  python3 scripts/read_db.py search <từ_khóa>    # Tìm kiếm CVE/CWE theo từ khóa (vd: apache, ssh)
"""

import sys
import sqlite3
import pathlib

DB_PATH = pathlib.Path(
    __file__).resolve().parent.parent / "toolkit" / "data" / "kb.sqlite"


def get_connection():
    if not DB_PATH.exists():
        print(f"[!] Không tìm thấy file CSDL tại: {DB_PATH}")
        print("[!] Hãy chạy: python3 run.py ingest để tạo CSDL trước.")
        sys.exit(1)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def show_overview():
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    tables = [r[0] for r in c.fetchall() if r[0] != 'sqlite_sequence']

    print(
        "\n==================================================================")
    print(f"[*] CƠ SỞ DỮ LIỆU: {DB_PATH}")
    print("==================================================================")
    print(f"{'TÊN BẢNG (TABLE)':<30} | {'SỐ DÒNG BẢN GHI':<15}")
    print("-" * 50)
    for table in tables:
        c.execute(f"SELECT COUNT(*) FROM {table}")
        count = c.fetchone()[0]
        print(f"{table:<30} | {count:<15}")
    print("==================================================================")
    print("[*] Gợi ý xem chi tiết:")
    print("    python3 scripts/read_db.py cve")
    print("    python3 scripts/read_db.py cwe")
    print("    python3 scripts/read_db.py search apache\n")


def view_table(table_name: str, limit: int = 5):
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute(f"SELECT * FROM {table_name} LIMIT ?", (limit, ))
        rows = c.fetchall()
        if not rows:
            print(f"[*] Bảng '{table_name}' hiện đang rỗng.")
            return

        cols = [d[0] for d in c.description]
        print(
            f"\n[*] Hiển thị {len(rows)} bản ghi đầu tiên của bảng: [{table_name}]"
        )
        print("=" * 70)
        for idx, row in enumerate(rows, 1):
            print(f"\n--- [Bản ghi #{idx}] ---")
            for col in cols:
                val = str(row[col])
                if len(val) > 120:
                    val = val[:117] + "..."
                print(f"  {col:<20}: {val}")
        print("=" * 70 + "\n")
    except sqlite3.OperationalError as e:
        print(f"[!] Lỗi truy vấn bảng '{table_name}': {e}")


def search_cve(keyword: str):
    conn = get_connection()
    c = conn.cursor()
    print(f"\n[*] Đang tìm kiếm với từ khóa: '{keyword}'...")
    query = """
        SELECT cve_id, cvss_v3_score, cvss_v3_severity, cwe_ids, description 
        FROM cve 
        WHERE cve_id LIKE ? OR description LIKE ?
        ORDER BY cvss_v3_score DESC
        LIMIT 5
    """
    param = f"%{keyword}%"
    c.execute(query, (param, param))
    rows = c.fetchall()
    if not rows:
        print(f"[!] Không tìm thấy bản ghi nào khớp với '{keyword}'.\n")
        return

    print(f"[+] Tìm thấy {len(rows)} bản ghi tiêu biểu:")
    print("=" * 70)
    for r in rows:
        print(
            f"Mã CVE    : {r['cve_id']} (Điểm: {r['cvss_v3_score']} - {r['cvss_v3_severity']})"
        )
        print(f"CWE       : {r['cwe_ids']}")
        print(f"Mô tả     : {r['description'][:150]}...")
        print("-" * 70)
    print("")


def main():
    if len(sys.argv) < 2:
        show_overview()
    elif sys.argv[1].lower() == "search":
        if len(sys.argv) < 3:
            print("Cách dùng: python3 scripts/read_db.py search <từ_khóa>")
        else:
            search_cve(sys.argv[2])
    else:
        table = sys.argv[1].lower()
        limit = int(
            sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 5
        view_table(table, limit)


if __name__ == "__main__":
    main()
