from flask import Flask, render_template, request, redirect, url_for, session, flash
from db_manager import DBManager
import jwt
import datetime
import redis
from functools import wraps
import json
from flask_session import Session
from pymongo import MongoClient
from datetime import datetime, timedelta
import csv
import io
from flask import Response
import threading
import uuid
import os

APP_INSTANCE_ID = f"{uuid.uuid4().hex}_{os.getpid()}"
print(f"[*] Запущен инстанс приложения с ID: {APP_INSTANCE_ID}")

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_stopik'
db = DBManager()

session_redis = redis.Redis(host='localhost', port=6379, db=0)

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

mongo_client = MongoClient('mongodb://localhost:27017/')
log_db = mongo_client['stopik_logs']
logs_collection = log_db['system_logs']
logs_collection.create_index("expire_at", expireAfterSeconds=0)


app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_REDIS'] = session_redis  # Используем твой существующий объект r
Session(app)

def redis_listener():
    """Отдельный поток для прослушивания сообщений от других инстансов"""
    pubsub = r.pubsub()
    pubsub.subscribe('data_updates')
    
    for message in pubsub.listen():
        if message['type'] == 'message':
            data = json.loads(message['data'])
            if data.get('sender_id') == APP_INSTANCE_ID:
                continue
            action = data.get('action')
            
            # Логика синхронизации: например, очистка локального кэша
            if action == 'invalidate_cache':
                key = data.get('key')
                # Здесь можно добавить логику очистки чего-то специфичного
                print(f"[*] Получен сигнал на очистку кэша: {key}")

threading.Thread(target=redis_listener, daemon=True).start()

def notify_data_change(action, key=None):
    message = json.dumps({
        'sender_id': APP_INSTANCE_ID,
        'action': action,
        'key': key,
        'timestamp': datetime.utcnow().isoformat()
    })
    r.publish('data_updates', message)



def save_log(event_type, action, user_id=None, details=None):
    """Универсальная функция для записи лога"""
    log_entry = {
        "timestamp": datetime.utcnow(),
        "event_type": event_type, 
        "action": action,
        "user_id": user_id,
        "details": details,
        "expire_at": datetime.utcnow() + timedelta(days=30) 
    }
    logs_collection.insert_one(log_entry)


app.config['JWT_SECRET'] = 'your_jwt_secret_key' 

@app.route('/')
def index():
    cache_key = "catalog:published_courses"
    cached_courses = get_cache(cache_key)
    
    if cached_courses:
        return render_template('index.html', courses=cached_courses)
    
    query = """
        SELECT c.id, c.title, c.price, cat.name as category_name 
        FROM Courses c
        JOIN Categories cat ON c.category_id = cat.id
        WHERE c.is_published = TRUE
    """
    courses = db.execute_query(query, fetch=True)
    
    # Кэшируем на 10 минут (600 секунд)
    set_cache(cache_key, courses, ttl=600)
    
    return render_template('index.html', courses=courses)


def check_bruteforce(email):
    
    if r.get(f"blacklist:{email}"):
        return True, "Аккаунт временно заблокирован на 10 минут."
    return False, None

def register_failed_attempt(email):
    
    attempts = r.incr(f"attempts:{email}")
    if attempts == 1:
        r.expire(f"attempts:{email}", 300) 
    
    if attempts >= 3:
        
        r.setex(f"blacklist:{email}", 600, "blocked")
        r.delete(f"attempts:{email}") 

        save_log("SECURITY", "ACCOUNT_BLOCKED", details=f"Email: {email} blocked after 3 failed attempts")

        return True, 0 
    
    return False, 3 - attempts 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # 1. Проверка блокировки
        is_blocked, message = check_bruteforce(email)
        if is_blocked:
            flash(message)
            return render_template('login.html')

        # 2. Поиск пользователя (твой существующий код с JOIN)
        user_query = """
            SELECT u.id, u.email, u.password, u.first_name, r.role_name 
            FROM Users u
            JOIN User_Roles ur ON u.id = ur.user_id
            JOIN Roles r ON ur.role_id = r.id
            WHERE u.email = %s
        """
        user = db.execute_query(user_query, (email,), fetch=True)

        # 3. Проверка пароля
        if user and user[0]['password'] == password:
            r.delete(f"attempts:{email}") # Сброс при успехе
            
            user_data = user[0]
            token = jwt.encode({
                'user_id': user_data['id'],
                'role': user_data['role_name'],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['JWT_SECRET'], algorithm='HS256')

            session['user_id'] = user_data['id']
            session['first_name'] = user_data['first_name']
            session['role'] = user_data['role_name']

            save_log("USER_ACTION", "LOGIN_SUCCESS", user_id=user_data['id'])

            resp = redirect(url_for('dashboard'))
            resp.set_cookie('access_token', token, httponly=True)
            return resp
        
        else:
            
            is_now_blocked, attempts_left = register_failed_attempt(email)
            save_log("USER_ACTION", "LOGIN_FAILED", details=f"Email: {email}")
            if is_now_blocked:
                flash("Слишком много неудачных попыток. Вы заблокированы на 10 минут.")
            else:
                flash(f"Неверный пароль. Осталось попыток: {attempts_left}")
            
            
    return render_template('login.html')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return redirect(url_for('login'))
        
        try:
            data = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
            # Добавляем id пользователя в аргументы функции для удобства
            current_user_id = data['user_id']
        except:
            return redirect(url_for('login'))
        
        return f(current_user_id, *args, **kwargs)
    return decorated

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        save_log("USER_ACTION", "LOGOUT", user_id=user_id)
    session.clear()
    resp = redirect(url_for('login'))
    resp.set_cookie('access_token', '', expires=0) # Удаляем токен
    return resp

@app.route('/dashboard')
@token_required
def dashboard(current_user_id):
    
    role_cache_key = get_cache_key("user:role", current_user_id)
    role = get_cache(role_cache_key)
    
    if not role:
        user_query = """
            SELECT r.role_name 
            FROM Roles r
            JOIN User_Roles ur ON r.id = ur.role_id
            WHERE ur.user_id = %s
        """
        user_data = db.execute_query(user_query, (current_user_id,), fetch=True)
        if not user_data:
            return redirect(url_for('logout'))
        role = user_data[0]['role_name']
        set_cache(role_cache_key, role, ttl=3600) # Кэш роли на 1 час

    session['role'] = role

    if role == 'admin':
        # 1. Получаем параметры из URL
        page = request.args.get('page', 1, type=int)
        per_page = 20  # Количество логов на одну страницу
        
        user_id_filter = request.args.get('user_id', type=int)
        event_type = request.args.get('event_type')
        days_ago = request.args.get('days', default=7, type=int)
        
        # 2. Строим фильтр
        filter_query = {}
        time_limit = datetime.utcnow() - timedelta(days=days_ago)
        filter_query["timestamp"] = {"$gte": time_limit}
        
        if user_id_filter:
            filter_query["user_id"] = user_id_filter
        if event_type and event_type != 'ALL':
            filter_query["event_type"] = event_type

        # 3. Считаем общее количество для пагинации
        total_logs = logs_collection.count_documents(filter_query)
        total_pages = (total_logs + per_page - 1) // per_page if total_logs > 0 else 1

        # 4. Получаем логи с отступом (skip) и лимитом
        logs = list(logs_collection.find(filter_query)
                    .sort("timestamp", -1)
                    .skip((page - 1) * per_page)
                    .limit(per_page))
        
        for log in logs:
            log['_id'] = str(log['_id'])
            
        reports = get_analytics_reports() 
        
        # 5. Формируем объект пагинации для шаблона
        pagination = {
            'current_page': page,
            'total_pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'total_logs': total_logs
        }
            
        return render_template('admin_dashboard.html', 
                               logs=logs, 
                               reports=reports,
                               pagination=pagination, # ОБЯЗАТЕЛЬНО ПЕРЕДАЕМ
                               now=datetime.now(),    # Чтобы не было ошибки Undefined
                               timedelta=timedelta,   # Чтобы не было ошибки Undefined
                               current_days=days_ago, # Для вкладки аналитики
                               current_filters={
                                   'user_id': user_id_filter,
                                   'event_type': event_type,
                                   'days': days_ago
                               })

    # 2. Кэширование содержимого дашборда (Аналитические запросы)
    dash_cache_key = get_cache_key("user:dash_content", current_user_id)
    cached_dash = get_cache(dash_cache_key)
    
    if cached_dash:
        # Распаковываем закэшированные данные в шаблон
        return render_template(f'{role}_dashboard.html', **cached_dash)

    dash_data = {}
    if role == 'admin':
        # Параметры фильтрации (берем из query string, если есть)
        days_ago = request.args.get('days', default=1, type=int)
        time_limit = datetime.utcnow() - timedelta(days=days_ago)
        
        # Запрос к MongoDB
        logs = list(logs_collection.find(
            {"timestamp": {"$gte": time_limit}}
        ).sort("timestamp", -1).limit(50)) # Последние 50 штук
        
        dash_data['logs'] = logs
        # Для админа также можем подгрузить курсы, как для студента
        my_courses_query = "SELECT c.* FROM Courses c JOIN Enrollments e ON c.id = e.course_id WHERE e.user_id = %s"
        dash_data['my_courses'] = db.execute_query(my_courses_query, (current_user_id,), fetch=True)

    elif role == 'student':
        my_courses_query = """
            SELECT c.* FROM Courses c
            JOIN Enrollments e ON c.id = e.course_id
            WHERE e.user_id = %s
        """
        available_query = """
            SELECT * FROM Courses 
            WHERE is_published = TRUE AND id NOT IN (
                SELECT course_id FROM Enrollments WHERE user_id = %s
            )
        """
        dash_data['my_courses'] = db.execute_query(my_courses_query, (current_user_id,), fetch=True)
        dash_data['available'] = db.execute_query(available_query, (current_user_id,), fetch=True)

    elif role == 'instructor':
        dash_data['courses'] = db.execute_query("SELECT * FROM Courses WHERE instructor_id = %s", (current_user_id,), fetch=True)
    
    # Кэшируем данные дашборда на 5 минут
    set_cache(dash_cache_key, dash_data, ttl=300)
    return render_template(f'{role}_dashboard.html', **dash_data)

@app.route('/lesson/<int:lesson_id>/add_page_section', methods=['POST'])
@token_required
def add_page_section(current_user_id, lesson_id):
    content = request.form.get('content')
    section_type = request.form.get('type', 'text') # text или code
    
    # 1. Находим или создаем страницу для этого урока (упростим: 1 урок = 1 страница)
    page = db.execute_query("SELECT id FROM LessonPages WHERE lesson_id=%s", (lesson_id,), fetch=True)
    if not page:
        db.execute_query("INSERT INTO LessonPages (lesson_id, title, order_in_lesson) VALUES (%s, 'Контент', 1)", (lesson_id,))
        page = db.execute_query("SELECT id FROM LessonPages WHERE lesson_id=%s", (lesson_id,), fetch=True)
    
    page_id = page[0]['id']
    
    # 2. Добавляем секцию
    last_order = db.execute_query("SELECT MAX(section_order) as m FROM PageSections WHERE page_id=%s", (page_id,), fetch=True)[0]['m'] or 0
    db.execute_query("""
        INSERT INTO PageSections (page_id, content, section_type, section_order) 
        VALUES (%s, %s, %s, %s)
    """, (page_id, content, section_type, last_order + 1))
    
    flash("Блок контента добавлен")
    save_log("USER_ACTION", "CREATE_SECTION", user_id=current_user_id, details=f"Lesson: {lesson_id}")
    return redirect(url_for('edit_lesson', lesson_id=lesson_id))

# Роут для удаления секции
@app.route('/delete_section/<int:section_id>')
@token_required
def delete_section(current_user_id, section_id):
    db.execute_query("DELETE FROM PageSections WHERE id=%s", (section_id,))
    save_log("USER_ACTION", "DELETE_SECTION", user_id=current_user_id, details=f"ID: {section_id}")
    return redirect(request.referrer)

@app.route('/edit_course/<int:course_id>', methods=['GET', 'POST'])
@token_required
def edit_course(current_user_id, course_id):
    if session.get('role') != 'instructor':
        flash("У вас нет прав для редактирования курсов.")
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = request.form.get('price')
        
        update_query = """
            UPDATE Courses 
            SET title=%s, description=%s, price=%s 
            WHERE id=%s AND instructor_id=%s
        """
        db.execute_query(update_query, (title, description, price, course_id, current_user_id))

        save_log("USER_ACTION", "COURSE_UPDATE", user_id=current_user_id, 
                 details=f"Course: {course_id}, New Price: {request.form.get('price')}")
        
        # --- ИНВАЛИДАЦИЯ КЭША ---
        r.delete("catalog:published_courses") # Сброс общего каталога
        r.delete(get_cache_key("user:dash_content", current_user_id)) # Сброс дашборда автора
        # ------------------------
        cache_key = "catalog:published_courses"
        notify_data_change('invalidate_cache', key=cache_key)
        
        flash("Курс успешно обновлен! Кэш очищен.")
        return redirect(url_for('dashboard'))
        
    course = db.execute_query("SELECT * FROM Courses WHERE id=%s AND instructor_id=%s", (course_id, current_user_id), fetch=True)
    if not course: return "404", 404

    modules = db.execute_query("SELECT * FROM Modules WHERE course_id=%s ORDER BY order_in_course", (course_id,), fetch=True)
    for m in modules:
        m['lessons'] = db.execute_query("SELECT * FROM Lessons WHERE module_id=%s ORDER BY order_in_module", (m['id'],), fetch=True)

    return render_template('edit_course.html', course=course[0], modules=modules)

@app.route('/course/<int:course_id>')
def course_detail(course_id):
    user_id = session.get('user_id')
    is_enrolled = False
    if user_id:
        # Проверяем, записан ли пользователь
        query = "SELECT 1 FROM Enrollments WHERE user_id = %s AND course_id = %s"
        result = db.execute_query(query, (user_id, course_id), fetch=True)
        if result:
            is_enrolled = True
    # 1. Получаем инфо о курсе
    course = db.execute_query("SELECT * FROM Courses WHERE id = %s", (course_id,), fetch=True)
    if not course: return "404", 404

    # 2. Получаем все модули курса
    modules = db.execute_query("SELECT * FROM Modules WHERE course_id = %s ORDER BY order_in_course", (course_id,), fetch=True)

    # 3. Получаем все уроки для этих модулей
    # Выбираем уроки, которые принадлежат любому модулю этого курса
    lessons_query = """
        SELECT l.* FROM Lessons l
        JOIN Modules m ON l.module_id = m.id
        WHERE m.course_id = %s
        ORDER BY m.order_in_course, l.order_in_module
    """
    lessons = db.execute_query(lessons_query, (course_id,), fetch=True)

    # Группируем уроки по модулям для удобства в шаблоне
    for module in modules:
        module['lessons'] = [l for l in lessons if l['module_id'] == module['id']]

    return render_template('course_detail.html', course=course[0], modules=modules,is_enrolled=is_enrolled)


# @app.errorhandler(Exception)
# def handle_exception(e):
#     save_log("ERROR", type(e).__name__, details=str(e), user_id=session.get('user_id'))
#     return "Произошла внутренняя ошибка сервера", 500

@app.route('/enroll/<int:course_id>', methods=['POST'])
def enroll(course_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    db.execute_query("INSERT INTO Enrollments (user_id, course_id) VALUES (%s, %s)", (user_id, course_id))
    save_log("USER_ACTION", "COURSE_ENROLL", user_id=user_id, details=f"Course ID: {course_id}")
    
    # --- ИНВАЛИДАЦИЯ КЭША ---
    r.delete(get_cache_key("user:dash_content", user_id)) # Обновляем дашборд студента
    # ------------------------
    
    flash("Вы успешно записались на курс!")
    return redirect(url_for('course_detail', course_id=course_id))

@app.route('/unenroll/<int:course_id>', methods=['POST'])
def unenroll(course_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    db.execute_query("DELETE FROM Enrollments WHERE user_id = %s AND course_id = %s", (user_id, course_id))

    save_log("USER_ACTION", "COURSE_UNENROLL", user_id=user_id, details=f"Course ID: {course_id}")
    
    # --- ИНВАЛИДАЦИЯ КЭША ---
    r.delete(get_cache_key("user:dash_content", user_id))
    # ------------------------
    
    flash("Вы отписались от курса.")
    return redirect(url_for('course_detail', course_id=course_id))

@app.route('/course/<int:course_id>/lesson/<int:lesson_id>/step/<int:step_index>')
def lesson_step(course_id, lesson_id, step_index):
    # 1. Загружаем структуру для сайдбара (как раньше)
    modules = db.execute_query("SELECT * FROM Modules WHERE course_id = %s ORDER BY order_in_course", (course_id,), fetch=True)
    lessons_all = db.execute_query("""
        SELECT l.* FROM Lessons l JOIN Modules m ON l.module_id = m.id 
        WHERE m.course_id = %s ORDER BY m.order_in_course, l.order_in_module
    """, (course_id,), fetch=True)
    for m in modules:
        m['lessons'] = [l for l in lessons_all if l['module_id'] == m['id']]

    # 2. Получаем данные урока
    lesson = db.execute_query("SELECT * FROM Lessons WHERE id = %s", (lesson_id,), fetch=True)[0]

    # 3. Собираем все "шаги" урока (Страницы + Тесты)
    pages = db.execute_query("SELECT id, title, order_in_lesson, 'page' as type FROM LessonPages WHERE lesson_id = %s", (lesson_id,), fetch=True)
    quizzes = db.execute_query("SELECT id, title, 999 as order_in_lesson, 'quiz' as type FROM Quizzes WHERE lesson_id = %s", (lesson_id,), fetch=True)
    
    # Объединяем и сортируем по order_in_lesson
    all_steps = sorted(pages + quizzes, key=lambda x: x['order_in_lesson'])

    # 4. Получаем контент для текущего шага
    current_step = all_steps[step_index]
    step_content = None

    if current_step['type'] == 'page':
        # Загружаем секции текста/кода
        step_content = db.execute_query("SELECT * FROM PageSections WHERE page_id = %s ORDER BY section_order", (current_step['id'],), fetch=True)
    else:
        # Загружаем вопросы теста
        step_content = db.execute_query("SELECT * FROM Questions WHERE quiz_id = %s", (current_step['id'],), fetch=True)
        # Декодируем JSON для каждого вопроса
        import json
        for q in step_content:
            if isinstance(q['answers'], str):
                q['answers'] = json.loads(q['answers'])

    return render_template('lesson.html', 
                           course_id=course_id,
                           modules=modules,
                           lesson=lesson,
                           steps=all_steps,
                           current_step=current_step,
                           step_index=step_index,
                           content=step_content)

# --- УПРАВЛЕНИЕ МОДУЛЯМИ ---

@app.route('/course/<int:course_id>/add_module', methods=['POST'])
@token_required
def add_module(current_user_id, course_id):
    title = request.form.get('title')
    # Узнаем последний порядок, чтобы поставить в конец
    last_order = db.execute_query("SELECT MAX(order_in_course) as m FROM Modules WHERE course_id=%s", (course_id,), fetch=True)[0]['m'] or 0
    
    db.execute_query("""
        INSERT INTO Modules (course_id, title, order_in_course) 
        VALUES (%s, %s, %s)
    """, (course_id, title, last_order + 1))
    flash("Модуль добавлен")
    save_log("USER_ACTION", "CREATE_MODULE", user_id=current_user_id, details=f"Course: {course_id}, Title: {title}")
    return redirect(url_for('edit_course', course_id=course_id))

@app.route('/delete_module/<int:module_id>')
@token_required
def delete_module(current_user_id, module_id):
    # Важно: сначала проверяем, что этот модуль принадлежит курсу этого учителя
    check = db.execute_query("""
        SELECT m.id FROM Modules m 
        JOIN Courses c ON m.course_id = c.id 
        WHERE m.id=%s AND c.instructor_id=%s
    """, (module_id, current_user_id), fetch=True)
    
    if check:
        db.execute_query("DELETE FROM Modules WHERE id=%s", (module_id,))
        save_log("USER_ACTION", "MODULE_DELETE", user_id=current_user_id, details=f"Module ID: {module_id}")
        flash("Модуль удален")
    return redirect(request.referrer)

# --- УПРАВЛЕНИЕ УРОКАМИ ---

@app.route('/module/<int:module_id>/add_lesson', methods=['POST'])
@token_required
def add_lesson(current_user_id, module_id):
    title = request.form.get('title')
    last_order = db.execute_query("SELECT MAX(order_in_module) as m FROM Lessons WHERE module_id=%s", (module_id,), fetch=True)[0]['m'] or 0
    
    db.execute_query("""
        INSERT INTO Lessons (module_id, title, order_in_module) 
        VALUES (%s, %s, %s)
    """, (module_id, title, last_order + 1))
    flash("Урок добавлен")
    save_log("USER_ACTION", "CREATE_LESSON", user_id=current_user_id, details=f"Module ID: {module_id}")
    return redirect(request.referrer)

# --- РЕДАКТИРОВАНИЕ КОНТЕНТА УРОКА ---

@app.route('/edit_lesson/<int:lesson_id>', methods=['GET', 'POST'])
@token_required
def edit_lesson(current_user_id, lesson_id):
    # Получаем урок и ID курса для кнопки "Назад"
    query = """
        SELECT l.*, m.course_id 
        FROM Lessons l
        JOIN Modules m ON l.module_id = m.id
        WHERE l.id = %s
    """
    lesson_data = db.execute_query(query, (lesson_id,), fetch=True)
    if not lesson_data: return "Урок не найден", 404
    lesson = lesson_data[0]

    if request.method == 'POST':
        # Обновление названия урока
        new_title = request.form.get('title')
        db.execute_query("UPDATE Lessons SET title=%s WHERE id=%s", (new_title, lesson_id))
        flash("Название урока обновлено")
        return redirect(url_for('edit_lesson', lesson_id=lesson_id))

    pages = db.execute_query("SELECT * FROM LessonPages WHERE lesson_id=%s", (lesson_id,), fetch=True)
    quizzes = db.execute_query("SELECT * FROM Quizzes WHERE lesson_id=%s", (lesson_id,), fetch=True)
    
    return render_template('edit_lesson.html', lesson=lesson, pages=pages, quizzes=quizzes, db=db)

@app.route('/edit_section/<int:section_id>', methods=['POST'])
@token_required
def edit_section(current_user_id, section_id):
    new_content = request.form.get('content')
    db.execute_query("UPDATE PageSections SET content=%s WHERE section_id=%s", (new_content, section_id))
    flash("Блок обновлен")
    save_log("USER_ACTION", "UPDATE_SECTION", user_id=current_user_id, details=f"Section ID: {section_id}")
    return redirect(request.referrer)

# НОВЫЙ РОУТ: Создание теста для урока
@app.route('/lesson/<int:lesson_id>/add_quiz', methods=['POST'])
@token_required
def add_quiz(current_user_id, lesson_id):
    title = request.form.get('title', 'Новый тест')
    db.execute_query("INSERT INTO Quizzes (title, lesson_id) VALUES (%s, %s)", (title, lesson_id))
    flash("Тест создан")
    save_log("USER_ACTION", "CREATE_QUIZ", user_id=current_user_id, details=f"Lesson ID: {lesson_id}")
    
    return redirect(request.referrer)

@app.route('/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@token_required
def edit_quiz(current_user_id, quiz_id):
    if request.method == 'POST':
        question_text = request.form.get('question_text')
        options = request.form.getlist('options[]')
        # Получаем индекс выбранного радио-баттона
        correct_idx = int(request.form.get('correct_option', 0))
        
        # Формируем структуру: {"correct": "значение", "options": ["сп", "ис", "ок"]}
        answers_dict = {
            "correct": options[correct_idx],
            "options": options
        }
        
        db.execute_query("""
            INSERT INTO Questions (text, answers, quiz_id) 
            VALUES (%s, %s, %s)
        """, (question_text, json.dumps(answers_dict, ensure_ascii=False), quiz_id))
        
        flash("Вопрос добавлен в формате БД")
        save_log("USER_ACTION", "CREATE_QUESTION", user_id=current_user_id, details=f"Quiz ID: {quiz_id}")
        return redirect(url_for('edit_quiz', quiz_id=quiz_id))

    quiz = db.execute_query("SELECT * FROM Quizzes WHERE id=%s", (quiz_id,), fetch=True)
    questions = db.execute_query("SELECT * FROM Questions WHERE quiz_id=%s", (quiz_id,), fetch=True)
    
    # Парсим JSON для отображения
    for q in questions:
        if isinstance(q['answers'], str):
            q['answers'] = json.loads(q['answers'])
            
    return render_template('edit_quiz.html', quiz=quiz[0], questions=questions)

# До кучи добавим удаление вопроса
@app.route('/delete_question/<int:question_id>')
@token_required
def delete_question(current_user_id, question_id):
    db.execute_query("DELETE FROM Questions WHERE id=%s", (question_id,))
    save_log("USER_ACTION", "DELETE_QUESTION", user_id=current_user_id, details=f"Question ID: {question_id}")  
    return redirect(request.referrer)

# Вспомогательная функция для генерации ключей кэша
def get_cache_key(prefix, *args):
    return f"{prefix}:" + ":".join(map(str, args))

# Сохранение в кэш с TTL
def set_cache(key, data, ttl=300):
    r.setex(key, ttl, json.dumps(data, default=str)) # default=str для обработки дат

# Получение из кэша
def get_cache(key):
    data = r.get(key)
    return json.loads(data) if data else None

# Удаление (инвалидация) по паттерну
def invalidate_cache(pattern):
    keys = r.keys(f"{pattern}*")
    if keys:
        r.delete(*keys)

def get_analytics_reports(days=7):
    reports = {}
    # Вычисляем дату начала периода
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Общий фильтр по времени для всех запросов
    time_filter = {"timestamp": {"$gte": start_date}}

    # 1. ТОП студентов (теперь с фильтром по периоду)
    reports['top_active_users'] = list(logs_collection.aggregate([
        {
            # Фильтруем по времени и исключаем системные логи (где user_id: 0 или None)
            "$match": { 
                **time_filter,
                "user_id": { 
                    "$exists": True, 
                    "$ne": None, 
                    "$gt": 0 
                }
            }
        },
        {
            "$group": {
                "_id": "$user_id", 
                "total_actions": {"$sum": 1} # Считаем все логи этого юзера
            }
        },
        {"$sort": {"total_actions": -1}},
        {"$limit": 10}
    ]))

    # 2. Чистая CRUD Статистика (с фильтром по периоду)
    crud_pipeline = [
        {
            "$match": {
                "action": { 
                    "$regex": "CREATE|ADD|ENROLL|UPDATE|EDIT|DELETE|REMOVE|UNENROLL", 
                    "$options": "i"
                },
                **time_filter # Добавляем фильтр времени
            }
        },
        {
            "$project": {
                "operation_type": {
                    "$switch": {
                        "branches": [
                            {"case": {"$regexMatch": {"input": "$action", "regex": "CREATE|ADD|ENROLL"}}, "then": "CREATE"},
                            {"case": {"$regexMatch": {"input": "$action", "regex": "UPDATE|EDIT"}}, "then": "UPDATE"},
                            {"case": {"$regexMatch": {"input": "$action", "regex": "DELETE|REMOVE|UNENROLL"}}, "then": "DELETE"}
                        ],
                        "default": "OTHER"
                    }
                }
            }
        },
        {"$group": {"_id": "$operation_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    reports['event_distribution'] = list(logs_collection.aggregate(crud_pipeline))

    if days <= 1:
        date_format = "%H:00"  # Можно использовать "%d.%m %H:00", если нужны и дата, и час
    else:
        date_format = "%Y-%m-%d"

    
    reports['time_series'] = list(logs_collection.aggregate([
        { "$match": time_filter },
        {
           
            "$addFields": {
                "ts_obj": { "$toDate": "$timestamp" }
            }
        },
        {
            "$group": {
                
                "_id": { "$dateToString": { "format": date_format, "date": "$ts_obj" } },
                "count": { "$sum": 1 }
            }
        },
        
        {"$sort": {"_id": 1}}
    ]))

    # 4. Аномалии (только LOGIN/LOGOUT за выбранный период)
    reports['anomalies'] = list(logs_collection.aggregate([
        {
            "$match": {
                **time_filter,
                # Фильтруем только события входа и выхода
                "action": {"$regex": "LOGIN|LOGOUT", "$options": "i"},
                "user_id": { 
                    "$exists": True, 
                    "$ne": None, 
                    "$gt": 0 
                }
            }
        },
        {
            "$group": {
                "_id": {
                    "user_id": "$user_id",
                    "hour": { "$dateToString": { "format": "%Y-%m-%d %H", "date": "$timestamp" } }
                },
                "actions": { "$sum": 1 }
            }
        },
        # Если за один час пользователь залогинился/вышел более 10 раз — это аномалия
        {"$match": {"actions": {"$gt": 10}}}, 
        {"$sort": {"actions": -1}}
    ]))

    return reports

@app.route('/admin/analytics')
@token_required
def admin_analytics(current_user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    
    # Получаем период из URL, по умолчанию 7 дней
    days = request.args.get('analytics_days', default=7, type=int)
    
    reports = get_analytics_reports(days=days)
    mock_filters = {
        'days': 7,
        'event_type': 'ALL',
        'user_id': None
    }
    return render_template(
        'admin_dashboard.html', # Твой правильный файл
        reports=reports, 
        current_days=days, 
        current_filters=mock_filters,
        now=datetime.utcnow(), 
        timedelta=timedelta,
        pagination=None
    )

@app.route('/admin/export/<report_type>/<format>')
@token_required
def export_report(current_user_id, report_type, format):
    if session.get('role') != 'admin':
        return "Access denied", 403

    # Берем количество дней из параметров запроса (как в основном роуте)
    days = request.args.get('days', default=7, type=int)
    reports = get_analytics_reports(days=days)
    data = reports.get(report_type, [])

    if not data:
        return "No data to export", 404

    # --- ЛОГИКА ДЛЯ JSON ---
    if format == 'json':
        return Response(
            json.dumps(data, default=str, ensure_ascii=False, indent=4),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment;filename={report_type}_{days}d.json'}
        )
    
    # --- ЛОГИКА ДЛЯ CSV ---
    elif format == 'csv':
        output = io.StringIO()
        # Ставим lineterminator, чтобы в Excel не было пустых строк
        writer = csv.writer(output, lineterminator='\n')
        
        # Подготовка заголовков и данных (особенно для аномалий)
        if report_type == 'anomalies':
            # Разворачиваем вложенный _id: {user_id, hour}
            writer.writerow(['user_id', 'hour', 'actions_count'])
            for row in data:
                writer.writerow([row['_id']['user_id'], row['_id']['hour'], row['actions']])
        
        elif report_type == 'top_active_users':
            writer.writerow(['user_id', 'total_actions'])
            for row in data:
                writer.writerow([row['_id'], row['total_actions']])
        
        else:
            # Универсальный вариант для простых списков (time_series, event_distribution)
            if data:
                writer.writerow(data[0].keys())
                for row in data:
                    writer.writerow(row.values())
        
        return Response(
            output.getvalue().encode('utf-8-sig'), # utf-8-sig для корректного открытия в Excel
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment;filename={report_type}_{days}d.csv'}
        )

    return "Unsupported format", 400

# @app.route('/submit_quiz/<int:quiz_id>', methods=['POST'])
# @token_required
# def submit_quiz(current_user_id, quiz_id):
#     # ... твой код проверки ответов и записи в Quiz_Attempts (MySQL) ...
    
#     # Если тест пройден успешно:
#     if is_passed:
#         # 1. Проверяем в MySQL, остались ли еще не пройденные тесты в этом уроке
#         # (Если этот тест был последним или единственным)
        
#         # 2. Логируем завершение урока в MongoDB
#         lesson_id = db.execute_query("SELECT lesson_id FROM Quizzes WHERE id=%s", (quiz_id,), fetch=True)[0]['lesson_id']
        
#         save_log("USER_PROGRESS", "LESSON_COMPLETED", user_id=current_user_id, details=f"Lesson ID: {lesson_id}")

if __name__ == '__main__':
    app.run(debug=True)