import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'interview_eval.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'judge'))
        );

        CREATE TABLE IF NOT EXISTS interviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            date TEXT NOT NULL,
            hire_count INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'ongoing' CHECK(status IN ('ongoing', 'completed')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS interview_judges (
            interview_id INTEGER NOT NULL,
            judge_id INTEGER NOT NULL,
            PRIMARY KEY (interview_id, judge_id),
            FOREIGN KEY (interview_id) REFERENCES interviews(id) ON DELETE CASCADE,
            FOREIGN KEY (judge_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS applicants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interview_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            field TEXT NOT NULL,
            age INTEGER,
            file_path TEXT,
            FOREIGN KEY (interview_id) REFERENCES interviews(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS evaluations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            applicant_id INTEGER NOT NULL,
            judge_id INTEGER NOT NULL,
            score1 INTEGER NOT NULL,
            score2 INTEGER NOT NULL,
            score3 INTEGER NOT NULL,
            score4 INTEGER NOT NULL,
            score5 INTEGER NOT NULL,
            total INTEGER NOT NULL,
            comment TEXT DEFAULT '',
            judgment TEXT DEFAULT '' CHECK(judgment IN ('', 'pass', 'hold', 'fail')),
            status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft', 'submitted')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(applicant_id, judge_id),
            FOREIGN KEY (applicant_id) REFERENCES applicants(id) ON DELETE CASCADE,
            FOREIGN KEY (judge_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interview_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            image_path TEXT NOT NULL,
            signed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(interview_id, user_id),
            FOREIGN KEY (interview_id) REFERENCES interviews(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS minutes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interview_id INTEGER UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft', 'confirmed')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (interview_id) REFERENCES interviews(id) ON DELETE CASCADE
        );
    ''')

    # Create default admin account
    admin_exists = cursor.execute(
        "SELECT id FROM users WHERE username = 'admin'"
    ).fetchone()
    if not admin_exists:
        cursor.execute(
            "INSERT INTO users (username, password_hash, name, role) VALUES (?, ?, ?, ?)",
            ('admin', generate_password_hash('admin123'), '산학협력단장', 'admin')
        )

    # Create default judge accounts
    for i in range(1, 4):
        judge_exists = cursor.execute(
            "SELECT id FROM users WHERE username = ?", (f'judge{i}',)
        ).fetchone()
        if not judge_exists:
            cursor.execute(
                "INSERT INTO users (username, password_hash, name, role) VALUES (?, ?, ?, ?)",
                (f'judge{i}', generate_password_hash(f'judge{i}'), f'심사위원{i}', 'judge')
            )

    conn.commit()
    conn.close()


if __name__ == '__main__':
    init_db()
    print("Database initialized successfully.")
