from pymongo import MongoClient
from datetime import datetime, timedelta
import random

# --- КОНФИГУРАЦИЯ ---
MONGO_URI = "mongodb://localhost:27017/"
MONGO_DB_NAME = "stopik_logs" # Убедись, что название совпадает с твоим в приложении

def seed_test_logs():
    try:
        # Подключение
        client = MongoClient(MONGO_URI)
        db = client[MONGO_DB_NAME]
        logs_col = db.system_logs
        
        # Очистим старые тестовые логи, если хочешь начать с чистого листа
        # logs_col.delete_many({"details": {"$regex": "Тест"}}) 

        print("🚀 Запуск генерации тестовых логов...")

        # 1. ГЕНЕРАЦИЯ CRUD ОПЕРАЦИЙ (для полосок прогресса)
        # Распределяем: много создания, средне правок, мало удалений
        # crud_actions = [
        #     ("CREATE", "CREATE_COURSE", 45),
        #     ("CREATE", "ADD_MODULE", 45),
        #     ("UPDATE", "UPDATE_COURSE", 35),
        #     ("UPDATE", "EDIT_SECTION", 35),
        #     ("DELETE", "DELETE_LESSON", 15),
        #     ("DELETE", "REMOVE_QUIZ", 10)
        # ]

        # for category, action, count in crud_actions:
        #     for _ in range(count):
        #         u_id = random.randint(1, 15) # Случайные ID пользователей
        #         logs_col.insert_one({
        #             "event_type": "USER_ACTION",
        #             "action": action,
        #             "user_id": u_id,
        #             "timestamp": datetime.utcnow() - timedelta(days=random.randint(0, 5)),
        #             "details": f"Тестовая операция {category}",
        #             "expire_at": datetime.utcnow() + timedelta(days=30)
        #         })
        # print("✅ CRUD операции добавлены.")

        # 2. ГЕНЕРАЦИЯ ПРОГРЕССА (для ТОП-10 студентов)
        # Сделаем пару "лидеров"
        print("-> Генерирую прогресс обучения (текстовые USER_ACTION)...")
        leaders = {1: 25, 5: 18, 10: 12, 3: 8} 
        
        for u_id, lesson_count in leaders.items():
            for i in range(lesson_count):
                # Генерируем случайные ID для имитации реальности
                c_id = random.randint(1, 3)
                m_id = random.randint(1, 5)
                l_id = 100 + i
                
                # Формируем строку деталей точно так же, как в твоем приложении
                log_details = f"Course ID: {c_id}, Module ID: {m_id}, Lesson ID: {l_id}"
                
                logs_col.insert_one({
                    "event_type": "USER_ACTION", # Как ты и просил
                    "action": "LESSON_COMPLETED",
                    "user_id": u_id,
                    "timestamp": datetime.utcnow() - timedelta(hours=i),
                    "details": log_details, 
                    "expire_at": datetime.utcnow() + timedelta(days=30)
                })
        print("✅ Данные о прогрессе добавлены в формате текстовой строки.")

        # 3. ГЕНЕРАЦИЯ АНОМАЛИИ (для красной таблицы)
        # Юзер 777 сделал 40 кликов за последние 10 минут
        # anomaly_user = 777
        # for _ in range(40):
        #     logs_col.insert_one({
        #         "event_type": "USER_ACTION",
        #         "action": "PAGE_VIEW",
        #         "user_id": anomaly_user,
        #         "timestamp": datetime.utcnow(),
        #         "details": "Тестовая аномалия (спам запросами)",
        #         "expire_at": datetime.utcnow() + timedelta(days=30)
        #     })
        # print("✅ Аномалия для ID 777 создана.")

        # # 4. СИСТЕМНЫЕ СОБЫТИЯ (для общего журнала)
        # logs_col.insert_one({
        #     "event_type": "SECURITY",
        #     "action": "BRUTEFORCE_BLOCK",
        #     "user_id": 0,
        #     "timestamp": datetime.utcnow(),
        #     "details": "IP 192.168.1.1 blocked after 5 attempts (Test)",
        #     "expire_at": datetime.utcnow() + timedelta(days=30)
        # })

        print("\n🎉 Все готово! Перезагрузи страницу админки.")

    except Exception as e:
        print(f"❌ Ошибка подключения к MongoDB: {e}")

if __name__ == "__main__":
    seed_test_logs()