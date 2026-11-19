"""Orders data access (fixture, parsed only, never imported).

`# expect: <category>` on a def line is the ground truth used to score the scanners.
"""
import corpdb

TABLE = "orders"
PAGE = 50


def by_id(order_id):
    return corpdb.execute("SELECT * FROM orders WHERE id = %s", (order_id,))


def by_status(status):  # expect: sqli
    q = "SELECT * FROM orders WHERE status = '" + status + "'"
    return corpdb.execute(q)


def by_customer(customer):  # expect: sqli
    return corpdb.execute(f"SELECT * FROM orders WHERE customer = '{customer}'")


def count_all():
    return corpdb.execute("SELECT COUNT(*) FROM " + TABLE)


def page(offset):
    offset = int(offset)
    sql = "SELECT * FROM orders LIMIT %d OFFSET %d" % (PAGE, offset)
    return corpdb.execute(sql)


def search(term):  # expect: sqli
    return corpdb.execute("SELECT * FROM orders WHERE note LIKE '%{}%'".format(term))
