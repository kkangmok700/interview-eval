import os
import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, make_response
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from database import get_db, init_db

app = Flask(__name__)
app.secret_key = 'interview-eval-secret-key-2024'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_APPLICANTS = os.path.join(BASE_DIR, 'uploads', 'applicants')
UPLOAD_SIGNATURES = os.path.join(BASE_DIR, 'uploads', 'signatures')

# 평가 항목 설정 (스크린샷 기반)
EVAL_CRITERIA = [
    {
        'id': 1,
        'name': '전문지식 및 근무환경 이해도',
        'max_score': 40,
        'scores': [40, 37, 33, 30, 27],
        'labels': ['탁월', '우수', '보통', '미흡', '매우 미흡'],
        'questions': [
            '수행하려는 학교의 기관(지역)의 업무를 타인에게는 어떤 것인지?',
            '담당 업무 전문성이 뛰어난 것으로 보이는가?',
            '사용할 지식·경험·비전·사회공헌의식 이끌어(건의 의) 능력적으로 탁월성이 보이는 것인가?',
        ],
    },
    {
        'id': 2,
        'name': '컴퓨터 활용 능력',
        'max_score': 15,
        'scores': [15, 13, 11, 9, 7],
        'labels': ['탁월', '우수', '보통', '미흡', '매우 미흡'],
        'questions': [
            '컴퓨터(엑셀/파워포인트/워드 등)과의 활용능력이 뛰어난가?',
            '최근 IT 트렌드, 인터넷/사무 기반의 실행능력이 있는가?',
            '전산(ERP)의 이해와 능력이 보이는가?',
        ],
    },
    {
        'id': 3,
        'name': '의사표현 및 논리성',
        'max_score': 15,
        'scores': [15, 13, 11, 9, 7],
        'labels': ['탁월', '우수', '보통', '미흡', '매우 미흡'],
        'questions': [
            '답변들이 일관적 사물을 이해시키는 정확한 사물에게 어떤 의견을 미치는가?',
            '다양한 질문에 다면, 면접에서 어떤 대응을 하였는가?',
            '답변시에의 언어표현 능력, 원활한 커뮤니케이션이 가능한 사람인가?',
            '경험과의 연결 능력에서 좋은점이 보이는가?',
        ],
    },
    {
        'id': 4,
        'name': '예의, 품성 및 봉사',
        'max_score': 15,
        'scores': [15, 13, 11, 9, 7],
        'labels': ['탁월', '우수', '보통', '미흡', '매우 미흡'],
        'questions': [
            '진정한 인성/가치의 나타남 것으로 인간으로서 가치(패너시)를 느끼는가?',
            '차분하고 차식적 없는 모습에서 신뢰감/가치요소 또는 규칙적 거리감이 느껴지는가?',
        ],
    },
    {
        'id': 5,
        'name': '창의력/역지사지/발전 가능성',
        'max_score': 15,
        'scores': [15, 13, 11, 9, 7],
        'labels': ['탁월', '우수', '보통', '미흡', '매우 미흡'],
        'questions': [
            '자유롭고도 인성적이지, 책임감/리더 이후 강점에 대한 질문에 답할 수 있는가?',
            '가정적이고 면접에서의 스스로의 모습까지의 모습은?',
            '인격적으로, 가정적이라는 것에 대한 부정의 느낌 없이 현재감 점수?',
        ],
    },
]

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'hwp'}
ALLOWED_SIG_EXTENSIONS = {'png', 'jpg', 'jpeg'}


def allowed_file(filename, extensions=None):
    if extensions is None:
        extensions = ALLOWED_EXTENSIONS
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions


# --- Auth decorators ---

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('관리자 권한이 필요합니다.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# --- Auth routes ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        db.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['name'] = user['name']
            session['role'] = user['role']
            flash(f'{user["name"]}님 환영합니다!', 'success')
            return redirect(url_for('dashboard'))
        flash('아이디 또는 비밀번호가 올바르지 않습니다.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.', 'info')
    return redirect(url_for('login'))


# --- Dashboard ---

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    if session['role'] == 'admin':
        interviews = db.execute(
            "SELECT * FROM interviews ORDER BY date DESC"
        ).fetchall()
        total_applicants = db.execute("SELECT COUNT(*) as cnt FROM applicants").fetchone()['cnt']
        total_interviews = len(interviews)
        completed = sum(1 for i in interviews if i['status'] == 'completed')
    else:
        interviews = db.execute('''
            SELECT i.* FROM interviews i
            JOIN interview_judges ij ON i.id = ij.interview_id
            WHERE ij.judge_id = ?
            ORDER BY i.date DESC
        ''', (session['user_id'],)).fetchall()
        total_applicants = 0
        total_interviews = len(interviews)
        completed = sum(1 for i in interviews if i['status'] == 'completed')
    db.close()
    return render_template('dashboard.html',
                           interviews=interviews,
                           total_interviews=total_interviews,
                           total_applicants=total_applicants,
                           completed=completed)


# --- Interview management ---

@app.route('/interviews')
@login_required
def interviews():
    db = get_db()
    if session['role'] == 'admin':
        interview_list = db.execute(
            "SELECT * FROM interviews ORDER BY date DESC"
        ).fetchall()
    else:
        interview_list = db.execute('''
            SELECT i.* FROM interviews i
            JOIN interview_judges ij ON i.id = ij.interview_id
            WHERE ij.judge_id = ?
            ORDER BY i.date DESC
        ''', (session['user_id'],)).fetchall()
    db.close()
    return render_template('interviews.html', interviews=interview_list)


@app.route('/interviews/create', methods=['GET', 'POST'])
@admin_required
def create_interview():
    db = get_db()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        date = request.form.get('date', '').strip()
        hire_count = int(request.form.get('hire_count', 1))
        judge_ids = request.form.getlist('judges')

        if not title or not date:
            flash('면접명과 날짜를 입력해주세요.', 'warning')
        elif len(judge_ids) == 0:
            flash('심사위원을 선택해주세요.', 'warning')
        else:
            cursor = db.execute(
                "INSERT INTO interviews (title, date, hire_count) VALUES (?, ?, ?)",
                (title, date, hire_count)
            )
            interview_id = cursor.lastrowid
            for jid in judge_ids:
                db.execute(
                    "INSERT INTO interview_judges (interview_id, judge_id) VALUES (?, ?)",
                    (interview_id, int(jid))
                )
            db.commit()
            flash('면접이 생성되었습니다.', 'success')
            db.close()
            return redirect(url_for('manage_applicants', interview_id=interview_id))

    judges = db.execute("SELECT * FROM users WHERE role = 'judge'").fetchall()
    db.close()
    return render_template('create_interview.html', judges=judges)


# --- Applicant management ---

@app.route('/interviews/<int:interview_id>/applicants', methods=['GET', 'POST'])
@admin_required
def manage_applicants(interview_id):
    db = get_db()
    interview = db.execute("SELECT * FROM interviews WHERE id = ?", (interview_id,)).fetchone()
    if not interview:
        flash('면접을 찾을 수 없습니다.', 'danger')
        db.close()
        return redirect(url_for('interviews'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        field = request.form.get('field', '').strip()
        age = request.form.get('age', '').strip()
        age = int(age) if age else None
        file = request.files.get('file')

        if not name or not field:
            flash('이름과 지원분야를 입력해주세요.', 'warning')
        else:
            file_path = None
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(f"{interview_id}_{name}_{file.filename}")
                file_path = os.path.join(UPLOAD_APPLICANTS, filename)
                file.save(file_path)
                file_path = filename

            db.execute(
                "INSERT INTO applicants (interview_id, name, field, age, file_path) VALUES (?, ?, ?, ?, ?)",
                (interview_id, name, field, age, file_path)
            )
            db.commit()
            flash(f'{name} 지원자가 등록되었습니다.', 'success')

    applicants = db.execute(
        "SELECT * FROM applicants WHERE interview_id = ?", (interview_id,)
    ).fetchall()
    db.close()
    return render_template('applicants.html', interview=interview, applicants=applicants)


@app.route('/applicants/<int:applicant_id>/delete', methods=['POST'])
@admin_required
def delete_applicant(applicant_id):
    db = get_db()
    applicant = db.execute("SELECT * FROM applicants WHERE id = ?", (applicant_id,)).fetchone()
    if applicant:
        if applicant['file_path']:
            filepath = os.path.join(UPLOAD_APPLICANTS, applicant['file_path'])
            if os.path.exists(filepath):
                os.remove(filepath)
        db.execute("DELETE FROM applicants WHERE id = ?", (applicant_id,))
        db.commit()
        flash('지원자가 삭제되었습니다.', 'info')
        db.close()
        return redirect(url_for('manage_applicants', interview_id=applicant['interview_id']))
    db.close()
    return redirect(url_for('interviews'))


@app.route('/uploads/applicants/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(UPLOAD_APPLICANTS, filename)


# --- Evaluation ---

@app.route('/interviews/<int:interview_id>/evaluate')
@login_required
def evaluate_list(interview_id):
    """심사위원이 지원자 목록을 보고 평가할 지원자를 선택하는 화면"""
    db = get_db()
    interview = db.execute("SELECT * FROM interviews WHERE id = ?", (interview_id,)).fetchone()
    if not interview:
        flash('면접을 찾을 수 없습니다.', 'danger')
        db.close()
        return redirect(url_for('interviews'))

    if session['role'] == 'judge':
        is_judge = db.execute(
            "SELECT 1 FROM interview_judges WHERE interview_id = ? AND judge_id = ?",
            (interview_id, session['user_id'])
        ).fetchone()
        if not is_judge:
            flash('이 면접의 심사위원이 아닙니다.', 'danger')
            db.close()
            return redirect(url_for('interviews'))

    applicants = db.execute(
        "SELECT * FROM applicants WHERE interview_id = ?", (interview_id,)
    ).fetchall()

    # Get evaluation status for each applicant
    eval_status = {}
    if session['role'] == 'judge':
        evals = db.execute('''
            SELECT applicant_id, status FROM evaluations
            WHERE judge_id = ? AND applicant_id IN (SELECT id FROM applicants WHERE interview_id = ?)
        ''', (session['user_id'], interview_id)).fetchall()
        for e in evals:
            eval_status[e['applicant_id']] = e['status']

    db.close()
    return render_template('evaluate_list.html',
                           interview=interview,
                           applicants=applicants,
                           eval_status=eval_status)


@app.route('/interviews/<int:interview_id>/evaluate/<int:applicant_id>', methods=['GET', 'POST'])
@login_required
def evaluate(interview_id, applicant_id):
    """개별 지원자 평가 화면 (스크린샷 기반 UI)"""
    db = get_db()
    interview = db.execute("SELECT * FROM interviews WHERE id = ?", (interview_id,)).fetchone()
    applicant = db.execute("SELECT * FROM applicants WHERE id = ?", (applicant_id,)).fetchone()

    if not interview or not applicant:
        flash('면접 또는 지원자를 찾을 수 없습니다.', 'danger')
        db.close()
        return redirect(url_for('interviews'))

    if session['role'] == 'judge':
        is_judge = db.execute(
            "SELECT 1 FROM interview_judges WHERE interview_id = ? AND judge_id = ?",
            (interview_id, session['user_id'])
        ).fetchone()
        if not is_judge:
            flash('이 면접의 심사위원이 아닙니다.', 'danger')
            db.close()
            return redirect(url_for('interviews'))

    if request.method == 'POST' and session['role'] == 'judge':
        scores = []
        for i in range(1, 6):
            score = int(request.form.get(f'score{i}', 0))
            scores.append(score)
        total = sum(scores)
        comment = request.form.get('comment', '').strip()
        judgment = request.form.get('judgment', '')
        submit_type = request.form.get('submit_type', 'draft')
        status = 'submitted' if submit_type == 'submit' else 'draft'

        existing = db.execute(
            "SELECT id FROM evaluations WHERE applicant_id = ? AND judge_id = ?",
            (applicant_id, session['user_id'])
        ).fetchone()

        if existing:
            db.execute('''
                UPDATE evaluations
                SET score1=?, score2=?, score3=?, score4=?, score5=?, total=?,
                    comment=?, judgment=?, status=?
                WHERE applicant_id=? AND judge_id=?
            ''', (*scores, total, comment, judgment, status, applicant_id, session['user_id']))
        else:
            db.execute('''
                INSERT INTO evaluations
                (applicant_id, judge_id, score1, score2, score3, score4, score5, total, comment, judgment, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (applicant_id, session['user_id'], *scores, total, comment, judgment, status))
        db.commit()

        if status == 'submitted':
            flash('평가가 최종 제출되었습니다.', 'success')
        else:
            flash('임시 저장되었습니다.', 'info')
        db.close()
        return redirect(url_for('evaluate_list', interview_id=interview_id))

    # Get existing evaluation
    my_eval = None
    if session['role'] == 'judge':
        my_eval = db.execute(
            "SELECT * FROM evaluations WHERE applicant_id = ? AND judge_id = ?",
            (applicant_id, session['user_id'])
        ).fetchone()

    db.close()
    return render_template('evaluate.html',
                           interview=interview,
                           applicant=applicant,
                           my_eval=my_eval,
                           criteria=EVAL_CRITERIA)


# --- Results ---

@app.route('/interviews/<int:interview_id>/results')
@login_required
def results(interview_id):
    db = get_db()
    interview = db.execute("SELECT * FROM interviews WHERE id = ?", (interview_id,)).fetchone()
    if not interview:
        flash('면접을 찾을 수 없습니다.', 'danger')
        db.close()
        return redirect(url_for('interviews'))

    applicants = db.execute(
        "SELECT * FROM applicants WHERE interview_id = ?", (interview_id,)
    ).fetchall()

    judges = db.execute('''
        SELECT u.* FROM users u
        JOIN interview_judges ij ON u.id = ij.judge_id
        WHERE ij.interview_id = ?
    ''', (interview_id,)).fetchall()

    results_data = []
    for applicant in applicants:
        evals = db.execute(
            "SELECT * FROM evaluations WHERE applicant_id = ? AND status = 'submitted'",
            (applicant['id'],)
        ).fetchall()

        judge_scores = {}
        for e in evals:
            judge_scores[e['judge_id']] = {
                'scores': [e['score1'], e['score2'], e['score3'], e['score4'], e['score5']],
                'total': e['total'],
                'comment': e['comment'],
                'judgment': e['judgment'],
            }

        total_average = 0
        if evals:
            total_average = sum(e['total'] for e in evals) / len(evals)

        eval_complete = len(evals) == len(judges)

        results_data.append({
            'applicant': applicant,
            'judge_scores': judge_scores,
            'total_average': round(total_average, 2),
            'eval_complete': eval_complete,
            'pass_threshold': total_average >= 70
        })

    results_data.sort(key=lambda x: x['total_average'], reverse=True)

    hire_count = interview['hire_count']
    passed_count = 0
    for r in results_data:
        if r['eval_complete'] and r['pass_threshold'] and passed_count < hire_count:
            r['result'] = '합격'
            passed_count += 1
        elif r['eval_complete'] and not r['pass_threshold']:
            r['result'] = '탈락 (기준미달)'
        elif r['eval_complete']:
            r['result'] = '탈락 (정원초과)'
        else:
            r['result'] = '평가 진행중'

    all_complete = all(r['eval_complete'] for r in results_data) and len(results_data) > 0

    db.close()
    return render_template('results.html',
                           interview=interview,
                           results=results_data,
                           judges=judges,
                           criteria=EVAL_CRITERIA,
                           all_complete=all_complete)


@app.route('/interviews/<int:interview_id>/complete', methods=['POST'])
@admin_required
def complete_interview(interview_id):
    db = get_db()
    db.execute("UPDATE interviews SET status = 'completed' WHERE id = ?", (interview_id,))
    db.commit()
    db.close()
    flash('면접이 완료 처리되었습니다.', 'success')
    return redirect(url_for('results', interview_id=interview_id))


# --- Minutes (회의록) ---

@app.route('/interviews/<int:interview_id>/minutes', methods=['GET', 'POST'])
@login_required
def minutes(interview_id):
    db = get_db()
    interview = db.execute("SELECT * FROM interviews WHERE id = ?", (interview_id,)).fetchone()
    if not interview:
        flash('면접을 찾을 수 없습니다.', 'danger')
        db.close()
        return redirect(url_for('interviews'))

    if request.method == 'POST':
        file = request.files.get('signature')
        if file and file.filename and allowed_file(file.filename, ALLOWED_SIG_EXTENSIONS):
            filename = secure_filename(f"sig_{interview_id}_{session['user_id']}_{file.filename}")
            filepath = os.path.join(UPLOAD_SIGNATURES, filename)
            file.save(filepath)

            existing = db.execute(
                "SELECT id FROM signatures WHERE interview_id = ? AND user_id = ?",
                (interview_id, session['user_id'])
            ).fetchone()

            if existing:
                db.execute(
                    "UPDATE signatures SET image_path = ?, signed_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (filename, existing['id'])
                )
            else:
                db.execute(
                    "INSERT INTO signatures (interview_id, user_id, image_path) VALUES (?, ?, ?)",
                    (interview_id, session['user_id'], filename)
                )
            db.commit()
            flash('서명이 등록되었습니다.', 'success')
        else:
            flash('PNG 또는 JPG 이미지 파일을 업로드해주세요.', 'warning')

    applicants = db.execute(
        "SELECT * FROM applicants WHERE interview_id = ?", (interview_id,)
    ).fetchall()

    judges = db.execute('''
        SELECT u.* FROM users u
        JOIN interview_judges ij ON u.id = ij.judge_id
        WHERE ij.interview_id = ?
    ''', (interview_id,)).fetchall()

    admin = db.execute("SELECT * FROM users WHERE role = 'admin'").fetchone()

    results_data = []
    for applicant in applicants:
        evals = db.execute(
            "SELECT * FROM evaluations WHERE applicant_id = ? AND status = 'submitted'",
            (applicant['id'],)
        ).fetchall()
        judge_scores = {}
        for e in evals:
            judge_scores[e['judge_id']] = {
                'scores': [e['score1'], e['score2'], e['score3'], e['score4'], e['score5']],
                'total': e['total'],
            }
        total_average = 0
        if evals:
            total_average = sum(e['total'] for e in evals) / len(evals)
        results_data.append({
            'applicant': applicant,
            'judge_scores': judge_scores,
            'total_average': round(total_average, 2),
        })
    results_data.sort(key=lambda x: x['total_average'], reverse=True)

    hire_count = interview['hire_count']
    passed_count = 0
    for r in results_data:
        if r['total_average'] >= 70 and passed_count < hire_count:
            r['result'] = '합격'
            passed_count += 1
        elif r['total_average'] < 70:
            r['result'] = '탈락'
        else:
            r['result'] = '탈락 (정원초과)'

    signatures = {}
    sig_rows = db.execute(
        "SELECT * FROM signatures WHERE interview_id = ?", (interview_id,)
    ).fetchall()
    for s in sig_rows:
        signatures[s['user_id']] = s

    required_signers = [admin['id']] + [j['id'] for j in judges] if admin else [j['id'] for j in judges]
    all_signed = all(uid in signatures for uid in required_signers)

    minute = db.execute(
        "SELECT * FROM minutes WHERE interview_id = ?", (interview_id,)
    ).fetchone()
    if not minute:
        db.execute("INSERT INTO minutes (interview_id) VALUES (?)", (interview_id,))
        db.commit()
        minute = db.execute("SELECT * FROM minutes WHERE interview_id = ?", (interview_id,)).fetchone()

    if all_signed and minute['status'] == 'draft':
        db.execute("UPDATE minutes SET status = 'confirmed' WHERE interview_id = ?", (interview_id,))
        db.commit()

    db.close()
    return render_template('minutes.html',
                           interview=interview,
                           results=results_data,
                           judges=judges,
                           admin=admin,
                           signatures=signatures,
                           all_signed=all_signed,
                           criteria=EVAL_CRITERIA,
                           required_signers=required_signers)


@app.route('/uploads/signatures/<filename>')
@login_required
def uploaded_signature(filename):
    return send_from_directory(UPLOAD_SIGNATURES, filename)


@app.route('/interviews/<int:interview_id>/minutes/pdf')
@login_required
def minutes_pdf(interview_id):
    db = get_db()
    interview = db.execute("SELECT * FROM interviews WHERE id = ?", (interview_id,)).fetchone()
    if not interview:
        db.close()
        return "면접을 찾을 수 없습니다.", 404

    applicants = db.execute(
        "SELECT * FROM applicants WHERE interview_id = ?", (interview_id,)
    ).fetchall()

    judges = db.execute('''
        SELECT u.* FROM users u
        JOIN interview_judges ij ON u.id = ij.judge_id
        WHERE ij.interview_id = ?
    ''', (interview_id,)).fetchall()

    admin = db.execute("SELECT * FROM users WHERE role = 'admin'").fetchone()

    results_data = []
    for applicant in applicants:
        evals = db.execute(
            "SELECT * FROM evaluations WHERE applicant_id = ? AND status = 'submitted'",
            (applicant['id'],)
        ).fetchall()
        judge_scores = {}
        for e in evals:
            judge_scores[e['judge_id']] = {
                'scores': [e['score1'], e['score2'], e['score3'], e['score4'], e['score5']],
                'total': e['total'],
            }
        total_average = 0
        if evals:
            total_average = sum(e['total'] for e in evals) / len(evals)
        results_data.append({
            'applicant': applicant,
            'judge_scores': judge_scores,
            'total_average': round(total_average, 2),
        })
    results_data.sort(key=lambda x: x['total_average'], reverse=True)

    hire_count = interview['hire_count']
    passed_count = 0
    for r in results_data:
        if r['total_average'] >= 70 and passed_count < hire_count:
            r['result'] = '합격'
            passed_count += 1
        elif r['total_average'] < 70:
            r['result'] = '탈락'
        else:
            r['result'] = '탈락 (정원초과)'

    signatures = {}
    sig_rows = db.execute(
        "SELECT * FROM signatures WHERE interview_id = ?", (interview_id,)
    ).fetchall()
    for s in sig_rows:
        signatures[s['user_id']] = s

    db.close()

    html = render_template('minutes_pdf.html',
                           interview=interview,
                           results=results_data,
                           judges=judges,
                           admin=admin,
                           signatures=signatures,
                           criteria=EVAL_CRITERIA,
                           upload_path=UPLOAD_SIGNATURES)

    try:
        from weasyprint import HTML
        pdf = HTML(string=html, base_url=request.url_root).write_pdf()
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=minutes_{interview_id}.pdf'
        return response
    except ImportError:
        return html


# --- User management ---

@app.route('/users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    db = get_db()
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        name = request.form.get('name', '').strip()
        role = request.form.get('role', 'judge')

        if not username or not password or not name:
            flash('모든 필드를 입력해주세요.', 'warning')
        else:
            existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                flash('이미 존재하는 아이디입니다.', 'danger')
            else:
                db.execute(
                    "INSERT INTO users (username, password_hash, name, role) VALUES (?, ?, ?, ?)",
                    (username, generate_password_hash(password), name, role)
                )
                db.commit()
                flash(f'{name} 사용자가 등록되었습니다.', 'success')

    users = db.execute("SELECT * FROM users ORDER BY role, name").fetchall()
    db.close()
    return render_template('users.html', users=users)


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('자기 자신은 삭제할 수 없습니다.', 'danger')
        return redirect(url_for('manage_users'))
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    flash('사용자가 삭제되었습니다.', 'info')
    return redirect(url_for('manage_users'))


if __name__ == '__main__':
    os.makedirs(UPLOAD_APPLICANTS, exist_ok=True)
    os.makedirs(UPLOAD_SIGNATURES, exist_ok=True)
    init_db()
    print("=" * 50)
    print("  면접 평가 시스템 시작")
    print("  http://localhost:5000")
    print("  관리자: admin / admin123")
    print("  심사위원: judge1~3 / judge1~3")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
