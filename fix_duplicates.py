import sqlite3

conn = sqlite3.connect('database.db')
cur = conn.cursor()
sql = 'select packet_time, COUNT(packet_time) as cp from packets GROUP BY packet_time HAVING cp > 1'
while True:
    cur.execute(sql)
    res = cur.fetchall()
    if len(res) == 0 or res is None:
        break
    for row in res:
        packet_time, cu = row
        cur.execute('select packet_id from packets where packet_time = ? order by packet_id', (packet_time, ))
        cur.execute('update packets set packet_time = ? where packet_id = ?', (packet_time + 1, cur.fetchone()[0]))
    conn.commit()