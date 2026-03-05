from flask import Flask, render_template, request, redirect, url_for, session, flash
from db_manager import DBManager
import jwt
import datetime
import redis
from functools import wraps

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_stopik'
db = DBManager()


r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

app.config['JWT_SECRET'] = 'your_jwt_secret_key' 

@app.route('/')
def index():
    
    query = """
        SELECT c.id, c.title, c.price, cat.name as category_name 
        FROM Courses c
        JOIN Categories cat ON c.category_id = cat.id
        WHERE c.is_published = TRUE
    """
    courses = db.execute_query(query, fetch=True)
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
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['JWT_SECRET'], algorithm='HS256')

            session['user_id'] = user_data['id']
            session['first_name'] = user_data['first_name']
            session['role'] = user_data['role_name']

            resp = redirect(url_for('dashboard'))
            resp.set_cookie('access_token', token, httponly=True)
            return resp
        
        else:
            
            is_now_blocked, attempts_left = register_failed_attempt(email)
            
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
    session.clear()
    resp = redirect(url_for('login'))
    resp.set_cookie('access_token', '', expires=0) # Удаляем токен
    return resp

@app.route('/dashboard')
@token_required
def dashboard(current_user_id):
    # Исправленный запрос с JOIN, чтобы найти роль пользователя
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
    
    # Сохраняем роль в сессию на случай, если другие роуты её используют
    session['role'] = role

    if role == 'student':
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
        my_courses = db.execute_query(my_courses_query, (current_user_id,), fetch=True)
        available_courses = db.execute_query(available_query, (current_user_id,), fetch=True)
        
        return render_template('student_dashboard.html', my_courses=my_courses, available=available_courses)

    elif role == 'instructor':
        created_courses = db.execute_query("SELECT * FROM Courses WHERE instructor_id = %s", (current_user_id,), fetch=True)
        return render_template('instructor_dashboard.html', courses=created_courses)
    
    return "Роль не распознана", 403

@app.route('/edit_course/<int:course_id>', methods=['GET', 'POST'])
def edit_course(course_id):
    if session.get('role') != 'instructor':
        return "Доступ запрещен", 403
        
    if request.method == 'POST':
        title = request.form.get('title')
        desc = request.form.get('description')
        price = request.form.get('price')
        
        db.execute_query("""
            UPDATE Courses SET title=%s, description=%s, price=%s 
            WHERE id=%s AND instructor_id=%s
        """, (title, desc, price, course_id, session['user_id']))
        return redirect(url_for('dashboard'))
        
    course = db.execute_query("SELECT * FROM Courses WHERE id=%s", (course_id,), fetch=True)
    return render_template('edit_course.html', course=course[0])

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

# Добавьте это в app.py

@app.route('/enroll/<int:course_id>', methods=['POST'])
def enroll(course_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    # SQL для записи на курс
    db.execute_query("INSERT INTO Enrollments (user_id, course_id) VALUES (%s, %s)", (user_id, course_id))
    flash("Вы успешно записались на курс!")
    return redirect(url_for('course_detail', course_id=course_id))

@app.route('/unenroll/<int:course_id>', methods=['POST'])
def unenroll(course_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    # SQL для удаления записи
    db.execute_query("DELETE FROM Enrollments WHERE user_id = %s AND course_id = %s", (user_id, course_id))
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

if __name__ == '__main__':
    app.run(debug=True)