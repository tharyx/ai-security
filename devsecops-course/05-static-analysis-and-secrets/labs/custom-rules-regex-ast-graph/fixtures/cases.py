"""One weakness (SQL injection), fifteen shapes. Parsed only, never imported or run.

`# truth: vuln|safe` on a def line is the ground truth used to score the three detectors.
"""
import sys

from flask import request

TABLE = "orders"


def case_a_direct_fstring():  # truth: vuln
    uid = request.args.get("id")
    cur.execute(f"SELECT * FROM t WHERE id = '{uid}'")


def case_b_constant_query():  # truth: safe
    cur.execute("SELECT 1")


def case_c_constant_table_name():  # truth: safe
    cur.execute("SELECT * FROM " + TABLE)


def case_d_variable_indirection():  # truth: vuln
    uid = request.args.get("id")
    q = "SELECT * FROM t WHERE id = '" + uid + "'"
    cur.execute(q)


def case_e_int_cast():  # truth: safe
    uid = int(request.args["id"])
    cur.execute(f"SELECT * FROM t WHERE id = {uid}")


def case_f_parameterised():  # truth: safe
    uid = request.args.get("id")
    cur.execute("SELECT * FROM t WHERE id = %s", (uid,))


def build_query(uid):
    return "SELECT * FROM t WHERE id = '" + uid + "'"


def case_g_helper_function():  # truth: vuln
    uid = request.form["uid"]
    cur.execute(build_query(uid))


def case_h_validated_with_guard():  # truth: safe
    uid = request.args.get("id")
    if not uid.isdigit():
        abort(400)
    cur.execute("SELECT * FROM t WHERE id = " + uid)


def case_i_command_line_argument():  # truth: vuln
    name = sys.argv[1]
    cur.execute("SELECT * FROM t WHERE name = '%s'" % name)


def case_j_constant_folding():  # truth: safe
    cur.execute("SELECT * FROM " + "orders")


def case_k_tainted_but_unused():  # truth: safe
    uid = request.args.get("id")
    log.info("seen %s", uid)
    cur.execute("SELECT 1")


def case_l_format_on_request_value():  # truth: vuln
    cur.execute("SELECT * FROM t WHERE q = '{}'".format(request.args["q"]))


def case_m_json_body():  # truth: vuln
    data = request.get_json()
    name = data["name"]
    cur.execute("SELECT * FROM t WHERE name = '" + name + "'")


def case_n_overwritten_with_constant():  # truth: safe
    q = request.args["q"]
    q = "default"
    cur.execute("SELECT * FROM t WHERE tag = '" + q + "'")


def case_o_one_branch_tainted():  # truth: vuln
    if flag:
        q = request.args["q"]
    else:
        q = "x"
    cur.execute("SELECT * FROM t WHERE tag = '" + q + "'")
