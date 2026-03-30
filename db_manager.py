import mysql.connector
from mysql.connector import Error

class DBManager:
    def __init__(self):
        self.config = {
            'host': 'localhost',
            'user': 'root',
            'password': '1234',
            'database': 'stopik'
        }

    def execute_query(self, query, params=None, fetch=False):
        connection = None
        from app import save_log # Импорт внутри, чтобы избежать циклической зависимости
        save_log("DB_QUERY", "EXECUTE", details=query[:100]) # логируем первые 100 символов запроса
        try:
            connection = mysql.connector.connect(**self.config)
            cursor = connection.cursor(dictionary=True) # Получаем данные как словари
            cursor.execute(query, params or ()) 
            
            if fetch:
                result = cursor.fetchall()
            else:
                connection.commit()
                result = cursor.lastrowid
            
            return result
        except Error as e:
            print(f"Error: {e}")
            return None
        finally:
            if connection and connection.is_connected():
                cursor.close()
                connection.close()