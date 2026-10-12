import pymysql
import sys

# Forza la versione per Django
pymysql.version_info = (2, 2, 1, "final", 0)
pymysql.install_as_MySQLdb()

# Mappa il modulo per i controlli di sistema
sys.modules["MySQLdb"] = pymysql