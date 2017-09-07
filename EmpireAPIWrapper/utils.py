from .exceptions import *
def db_info(db_path):
    """
    Print the API Username, Password and Permanent token
    :param db_path: Path to db file
    :return:
    """

    import sqlite3
    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.OperationalError:
        raise SQLError.SQLDBNonExist('SQL DB Not Found') from None
    c = conn.cursor()

    table_name = 'config'
    api_username_col = 'api_username'
    api_password_col = 'api_password'
    api_perm_token_col = 'api_permanent_token'

    c.execute('SELECT {cn} FROM {tn}'.format(tn=table_name, cn=api_username_col))
    api_username_val = c.fetchone()

    c.execute('SELECT {cn} FROM {tn}'.format(tn=table_name, cn=api_password_col))
    api_password_val = c.fetchone()

    c.execute('SELECT {cn} FROM {tn}'.format(tn=table_name, cn=api_perm_token_col))
    api_perm_token_val = c.fetchone()

    print('[*] API Username: {}'.format(api_username_val[0]))
    print('[*] API Password: {}'.format(api_password_val[0]))
    print('[*] API Permant Token: {}'.format(api_perm_token_val[0]))
    conn.close()

if __name__ == '__main__':
    db_info('/opt/Empire/data/empire.db')