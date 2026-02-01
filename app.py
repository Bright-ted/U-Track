from datetime import datetime, timedelta, timezone
from datetime import time
from flask import Flask, request, render_template, redirect, url_for, session
from supabase import create_client
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
import uuid
from uuid import uuid4
from flask import request, jsonify
import json
import base64
from io import BytesIO
from PIL import Image
import requests

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

app = Flask(__name__)
app.secret_key = "dev_secret_key"

app.config['UPLOAD_FOLDER'] = 'static/uploads/profile_photos'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max file size

@app.context_processor
def inject_user():
    """Make current_user available in all templates"""
    from flask import g
    if not hasattr(g, 'current_user'):
        g.current_user = {}
        if 'user_id' in session:
            user_info = {}
            user_info['id'] = session['user_id']
            user_info['role'] = session.get('role')
            user_info['full_name'] = session.get('full_name', 'User')
            user_info['email'] = session.get('email', '')
            user_info['index_number'] = session.get('index_number')
            g.current_user = user_info
    return dict(current_user=g.current_user)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Add custom Jinja2 filter for datetime formatting
def format_datetime(value, format='medium'):
    if value is None:
        return ""
    
    if isinstance(value, str):
        # Try to parse the string as datetime
        try:
            # Handle ISO format with timezone
            if 'Z' in value:
                value = value.replace('Z', '+00:00')
            value = datetime.fromisoformat(value)
        except (ValueError, AttributeError):
            return value
    
    if format == 'full':
        format = "%A, %B %d, %Y at %I:%M %p"
    elif format == 'medium':
        format = "%b %d, %Y %I:%M %p"
    elif format == 'short':
        format = "%m/%d/%Y"
    elif format == 'time':
        format = "%I:%M %p"
    elif format == 'date':
        format = "%b %d, %Y"
    else:
        format = str(format)
    
    return value.strftime(format)

# Register the filter with Jinja2
app.jinja_env.filters['datetimeformat'] = format_datetime

# Initialize Supabase client (ONCE!)
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

MAX_DURATION = timedelta(hours=3)

def get_active_session(course_id):
    """
    Get the active session for a course with automatic expiration check.
    Returns None if no active session or session has expired.
    """
    try:
        resp = (
            supabase
            .table("class_sessions")
            .select("id, course_id, qr_seed, started_at, created_at, start_time, is_active, ended_at")
            .eq("course_id", course_id)
            .eq("is_active", True)
            .order("started_at", desc=True)
            .limit(1)
            .execute()
        )

        if not resp.data:
            return None

        session = resp.data[0]
        
        # Get session duration from database settings or use default
        session_duration = get_session_duration(course_id)
        
        # Parse started_at time
        started_at_str = (
            session.get("started_at")
            or session.get("created_at")
            or session.get("start_time")
        )
        
        if not started_at_str:
            # If no start time, use current time
            started_at_str = datetime.now(timezone.utc).isoformat()
            supabase.table("class_sessions").update({
                "started_at": started_at_str
            }).eq("id", session["id"]).execute()
            session["started_at"] = started_at_str

        try:
            started_at = datetime.fromisoformat(
                started_at_str.replace("Z", "+00:00")
            )
            now = datetime.now(timezone.utc)
            
            # Calculate session age
            session_age = now - started_at
            
            # Check if session has exceeded maximum duration
            if session_age > session_duration:
                # Auto-close expired session
                supabase.table("class_sessions").update({
                    "is_active": False,
                    "ended_at": now.isoformat(),
                    "ended_reason": "auto_expired"
                }).eq("id", session["id"]).execute()
                
                print(f"Session {session['id']} auto-expired after {session_age}")
                return None
            
            # Also check if session is too short (just started)
            # Minimum session time before allowing attendance
            min_session_time = timedelta(minutes=1)
            if session_age < min_session_time:
                session["just_started"] = True
            else:
                session["just_started"] = False
                
            # Add time remaining info
            time_remaining = session_duration - session_age
            session["time_remaining_seconds"] = time_remaining.total_seconds()
            session["time_remaining_formatted"] = format_timedelta(time_remaining)
            session["session_progress"] = (session_age.total_seconds() / session_duration.total_seconds()) * 100
            
        except Exception as e:
            print(f"Error parsing session time: {e}")
            return session

        return session

    except Exception as e:
        print(f"Error getting active session: {e}")
        return None


# Fix the get_session_duration function to work with your schema
def get_session_duration(course_id):
    """
    Get the session duration for a course.
    Uses default MAX_DURATION since your schema doesn't have course_settings table.
    """
    # Since your schema doesn't have course_settings, use default
    return MAX_DURATION  # 3 hours


def format_timedelta(td):
    """Format timedelta to human-readable string"""
    total_seconds = int(td.total_seconds())
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"


def get_all_expired_sessions():
    """
    Find and close all expired sessions across all courses.
    Should be called periodically (e.g., by a scheduler).
    """
    try:
        # Get all active sessions
        resp = (
            supabase
            .table("class_sessions")
            .select("id, course_id, started_at, created_at, start_time")
            .eq("is_active", True)
            .execute()
        )
        
        if not resp.data:
            return []
        
        expired_sessions = []
        now = datetime.now(timezone.utc)
        
        for session in resp.data:
            started_at_str = (
                session.get("started_at")
                or session.get("created_at")
                or session.get("start_time")
            )
            
            if not started_at_str:
                continue
                
            try:
                started_at = datetime.fromisoformat(
                    started_at_str.replace("Z", "+00:00")
                )
                session_duration = get_session_duration(session["course_id"])
                
                if now - started_at > session_duration:
                    # Expired session found
                    supabase.table("class_sessions").update({
                        "is_active": False,
                        "ended_at": now.isoformat(),
                        "ended_reason": "auto_expired"
                    }).eq("id", session["id"]).execute()
                    
                    expired_sessions.append(session["id"])
                    print(f"Auto-expired session {session['id']} for course {session['course_id']}")
                    
            except Exception as e:
                print(f"Error checking session {session['id']}: {e}")
                continue
        
        return expired_sessions
        
    except Exception as e:
        print(f"Error getting expired sessions: {e}")
        return []

START_LIMIT = time(6, 30)
END_LIMIT = time(20, 30)
MIN_DURATION = timedelta(hours=1)
MAX_DURATION = timedelta(hours=3)


def get_course_owned_by_lecturer(course_id, lecturer_id):
    result = (
        supabase
        .table("courses")
        .select("*")
        .eq("id", course_id)
        .eq("lecturer_id", lecturer_id)
        .single()
        .execute()
    )
    return result.data

def authenticate_user(identifier, password):
    # First, get the user by email
    user_response = (
        supabase
        .table("users")
        .select("*")
        .eq("email", identifier)
        .execute()
    )
    
    if not user_response.data:
        return None
    
    user = user_response.data[0]
    
    # Verify password
    if not check_password_hash(user["password_hash"], password):
        return None
    
    # If student, get their index_number from students table
    if user["role"] == "student":
        student_response = (
            supabase
            .table("students")
            .select("index_number")
            .eq("user_id", user["id"])
            .execute()
        )
        
        if student_response.data:
            # Add index_number to user dictionary
            user["index_number"] = student_response.data[0]["index_number"]
    
    return user

# Add these helper functions to app.py after the existing imports

def rotate_qr_seed(session_id):
    """Generate a new QR seed for a session"""
    try:
        new_seed = str(uuid.uuid4())
        
        supabase.table("class_sessions").update({
            "qr_seed": new_seed,
            "qr_updated_at": datetime.now(timezone.utc).isoformat()
        }).eq("id", session_id).execute()
        
        return new_seed
    except Exception as e:
        print(f"Error rotating QR seed: {e}")
        return None

def get_current_qr_seed(session_id):
    """Get the current QR seed for a session"""
    try:
        resp = (
            supabase
            .table("class_sessions")
            .select("qr_seed, qr_updated_at")
            .eq("id", session_id)
            .single()
            .execute()
        )
        
        if resp.data:
            return resp.data["qr_seed"]
        return None
    except Exception as e:
        print(f"Error getting QR seed: {e}")
        return None

def create_student_user(conn, email, password, full_name, index_number, programme, level, department):
    cursor = conn.cursor()

    user_id = str(uuid.uuid4())
    password_hash = generate_password_hash(password)

    try:
        # Insert into users table
        cursor.execute(
            """
            INSERT INTO users (id, email, password_hash, full_name, role)
            VALUES (%s, %s, %s, %s, 'student')
            """,
            (user_id, email, password_hash, full_name)
        )

        # Insert into students table
        cursor.execute(
            """
            INSERT INTO students (user_id, index_number, programme, level, department)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, index_number, programme, level, department)
        )

        conn.commit()
        return user_id

    except Exception as e:
        conn.rollback()
        raise e

    finally:
        cursor.close()



@app.route("/")
def role_select():
    return render_template("role_select.html")

@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "GET":
        return render_template("register.html")

    full_name = request.form.get("full_name")
    email = request.form.get("email")
    staff_id = request.form.get("staff_id")
    department = request.form.get("department")
    title = request.form.get("title")
    password = request.form.get("password")

    if not all([full_name, email, staff_id, department, title, password]):
        return render_template("register.html", error="All fields required")

    password_hash = generate_password_hash(password)

    user_id = str(uuid.uuid4())

    supabase.table("users").insert({
        "id": user_id,
        "email": email,
        "password_hash": password_hash,
        "full_name": full_name,
        "role": "lecturer"
    }).execute()

    supabase.table("lecturers").insert({
        "user_id": user_id,
        "staff_id": staff_id,
        "title": title,
        "department": department
    }).execute()

    return redirect(url_for("login_page"))

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return render_template("login.html")

    identifier = request.form.get("identifier")
    password = request.form.get("password")

    user_query = (
        supabase
        .table("users")
        .select("*")
        .eq("email", identifier)
        .execute()
    )

    if not user_query.data:
        return render_template("login.html", error="Invalid login")

    user = user_query.data[0]

    if user["role"] != "lecturer":
        return render_template("login.html", error="Access denied")

    if not check_password_hash(user["password_hash"], password):
        return render_template("login.html", error="Invalid login")

    session["user_id"] = user["id"]
    session["role"] = user["role"]

    return redirect(url_for("lecturer_dashboard"))

@app.route("/lecturer/dashboard")
def lecturer_dashboard():
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))

    user_id = session["user_id"]

    # Get user profile
    user_query = (
        supabase
        .table("users")
        .select("full_name, email")
        .eq("id", user_id)
        .single()
        .execute()
    )

    # Get lecturer details
    lecturer_query = (
        supabase
        .table("lecturers")
        .select("title, department, staff_id")
        .eq("user_id", user_id)
        .single()
        .execute()
    )

    profile = {
        "name": user_query.data["full_name"],
        "email": user_query.data["email"],
        "title": lecturer_query.data["title"],
        "department": lecturer_query.data["department"],
        "staff_id": lecturer_query.data["staff_id"]
    }

    # Get lecturer's courses count
    courses_query = (
        supabase
        .table("courses")
        .select("*", count="exact")
        .eq("lecturer_id", user_id)
        .execute()
    )
    
    courses_count = courses_query.count if hasattr(courses_query, 'count') else len(courses_query.data)

    # Get total students across all lecturer's courses
    students_count = 0
    if courses_query.data:
        # Get all course IDs for this lecturer
        course_ids = [course["id"] for course in courses_query.data]
        
        # Count unique students across all courses
        students_query = (
            supabase
            .table("course_registration")
            .select("student_id", count="exact")
            .in_("course_id", course_ids)
            .execute()
        )
        
        students_count = students_query.count if hasattr(students_query, 'count') else len(students_query.data)

    # Get active sessions count - FIXED QUERY
    active_sessions_query = (
        supabase
        .table("class_sessions")
        .select("*", count="exact")
        .eq("is_active", True)
        .execute()
    )
    
    active_sessions_count = active_sessions_query.count if hasattr(active_sessions_query, 'count') else len(active_sessions_query.data)

    # Filter active sessions for lecturer's courses
    if active_sessions_query.data and courses_query.data:
        course_ids = [course["id"] for course in courses_query.data]
        lecturer_active_sessions = [
            session for session in active_sessions_query.data 
            if session["course_id"] in course_ids
        ]
        active_sessions_count = len(lecturer_active_sessions)

    # Get flagged students count (students with 3+ absences in lecturer's courses)
    flagged_students_count = 0
    if courses_query.data:
        course_ids = [course["id"] for course in courses_query.data]
        
        # Get attendance summary for flagged students
        try:
            flagged_query = (
                supabase
                .table("attendance_summary")
                .select("*", count="exact")
                .eq("is_blacklisted", True)
                .in_("course_id", course_ids)
                .execute()
            )
            
            flagged_students_count = flagged_query.count if hasattr(flagged_query, 'count') else len(flagged_query.data)
        except:
            # If attendance_summary table doesn't exist yet, use 0
            flagged_students_count = 0

    return render_template(
        "lecturer_dashboard.html",
        profile=profile,
        courses_count=courses_count,
        students_count=students_count,
        active_sessions_count=active_sessions_count,
        flagged_students_count=flagged_students_count
    )

# Update the lecturer_courses route to include real statistics
@app.route("/lecturer/courses")
def lecturer_courses():
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))

    lecturer_id = session["user_id"]

    # Get courses with additional statistics
    courses = (
        supabase
        .table("courses")
        .select("*")
        .eq("lecturer_id", lecturer_id)
        .execute()
        .data
    )
    
    # Get statistics for each course
    courses_with_stats = []
    for course in courses:
        # Get student count for this course
        student_count = (
            supabase
            .table("course_registration")
            .select("*", count="exact")
            .eq("course_id", course["id"])
            .execute()
        )
        student_count = student_count.count if hasattr(student_count, 'count') else len(student_count.data)
        
        # Get session count for this course
        session_count = (
            supabase
            .table("class_sessions")
            .select("*", count="exact")
            .eq("course_id", course["id"])
            .execute()
        )
        session_count = session_count.count if hasattr(session_count, 'count') else len(session_count.data)
        
        # Get attendance percentage (if there are sessions)
        attendance_percent = "--%"
        if session_count > 0:
            # Get total possible attendance (students * sessions)
            total_possible = student_count * session_count
            if total_possible > 0:
                # Get actual attendance count
                attendance_count = (
                    supabase
                    .table("attendance")
                    .select("*", count="exact")
                    .in_("session_id", 
                        [s["id"] for s in supabase.table("class_sessions")
                         .select("id")
                         .eq("course_id", course["id"])
                         .execute().data]
                    )
                    .execute()
                )
                attendance_count = attendance_count.count if hasattr(attendance_count, 'count') else len(attendance_count.data)
                
                percent = (attendance_count / total_possible) * 100
                attendance_percent = f"{percent:.1f}%"
        
        # Add statistics to course
        course["student_count"] = student_count or 0
        course["session_count"] = session_count or 0
        course["attendance_percent"] = attendance_percent
        
        courses_with_stats.append(course)
    
    # Get overall statistics for the dashboard
    total_students = sum(course["student_count"] for course in courses_with_stats)
    
    # Get active sessions count
    active_sessions = (
        supabase
        .table("class_sessions")
        .select("*", count="exact")
        .eq("is_active", True)
        .execute()
    )
    active_sessions_count = active_sessions.count if hasattr(active_sessions, 'count') else len(active_sessions.data)
    
    # Calculate overall attendance rate (average of course percentages)
    if courses_with_stats:
        total_percent = 0
        valid_courses = 0
        for course in courses_with_stats:
            if course["attendance_percent"] != "--%":
                percent = float(course["attendance_percent"].replace('%', ''))
                total_percent += percent
                valid_courses += 1
        avg_attendance = f"{(total_percent / valid_courses if valid_courses > 0 else 0):.1f}%"
    else:
        avg_attendance = "0%"

    return render_template(
        "lecturer_courses.html", 
        courses=courses_with_stats,
        total_students=total_students,
        active_sessions_count=active_sessions_count,
        avg_attendance=avg_attendance
    )


@app.route("/lecturer/courses/create", methods=["GET", "POST"])
def create_course():
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))

    if request.method == "GET":
        return render_template("create_course.html")

    course_code = request.form.get("course_code")
    course_title = request.form.get("course_title")
    academic_year = request.form.get("academic_year")
    semester = request.form.get("semester")

    if not all([course_code, course_title, academic_year, semester]):
        return render_template("create_course.html", error="All fields required")

    supabase.table("courses").insert({
        "course_code": course_code,
        "course_title": course_title,
        "lecturer_id": session["user_id"],
        "academic_year": academic_year,
        "semester": int(semester)
    }).execute()

    return redirect(url_for("lecturer_courses"))

@app.route("/lecturer/courses/<course_id>/schedule", methods=["GET", "POST"])
def course_schedule(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))

    course = (
        supabase
        .table("courses")
        .select("*")
        .eq("id", course_id)
        .eq("lecturer_id", session["user_id"])
        .single()
        .execute()
        .data
    )

    if request.method == "GET":
        schedules = (
            supabase
            .table("course_schedule")
            .select("*")
            .eq("course_id", course_id)
            .execute()
            .data
        )
        return render_template(
            "course_schedule.html",
            course=course,
            schedules=schedules
        )

    day = request.form.get("day")
    start_time = request.form.get("start_time")
    end_time = request.form.get("end_time")
    venue = request.form.get("venue")

    if not all([day, start_time, end_time, venue]):
        return redirect(url_for("course_schedule", course_id=course_id))

    start_h, start_m = map(int, start_time.split(":"))
    end_h, end_m = map(int, end_time.split(":"))

    min_time = time(6, 30)
    max_time = time(20, 30)

    if not (min_time <= time(start_h, start_m) <= max_time):
        return redirect(url_for("course_schedule", course_id=course_id))

    if not (min_time <= time(end_h, end_m) <= max_time):
        return redirect(url_for("course_schedule", course_id=course_id))

    supabase.table("course_schedule").insert({
        "course_id": course_id,
        "day": day,
        "start_time": start_time,
        "end_time": end_time,
        "venue": venue
    }).execute()

    return redirect(url_for("course_schedule", course_id=course_id))

@app.route("/student/register-course/<course_id>", methods=["POST"])
def register_course(course_id):
    if session.get("role") != "student":
        return redirect("/student/login")
    
    student_id = session["user_id"]
    
    # Check if already registered
    existing = (
        supabase
        .table("course_registration")
        .select("*")
        .eq("course_id", course_id)
        .eq("student_id", student_id)
        .execute()
        .data
    )
    
    if existing:
        # Already registered, redirect back
        return redirect("/student/browse-courses")
    
    # Register for the course
    supabase.table("course_registration").insert({
        "course_id": course_id,
        "student_id": student_id
    }).execute()
    
    return redirect("/student/browse-courses")

    

@app.route("/lecturer/courses/<course_id>/students")
def lecturer_course_students(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))

    # Verify lecturer owns this course
    course = (
        supabase
        .table("courses")
        .select("*")
        .eq("id", course_id)
        .eq("lecturer_id", session["user_id"])
        .single()
        .execute()
        .data
    )

    if not course:
        return "Unauthorized", 403

    # Get students registered for this course with their details
    registrations = (
        supabase
        .table("course_registration")
        .select(
            """
            student_id,
            students(
                index_number,
                programme,
                level,
                department,
                users(
                    id,
                    full_name,
                    email,
                    profile_photo_url
                )
            )
            """
        )
        .eq("course_id", course_id)
        .execute()
        .data
    )

    # Process the data to flatten the structure
    students = []
    for reg in registrations:
        if reg.get('students') and reg['students'].get('users'):
            student_data = {
                'student_id': reg['student_id'],
                'index_number': reg['students']['index_number'],
                'programme': reg['students']['programme'],
                'level': reg['students']['level'],
                'department': reg['students']['department'],
                'full_name': reg['students']['users']['full_name'],
                'email': reg['students']['users']['email'],
                'profile_photo_url': reg['students']['users']['profile_photo_url']
            }
            students.append(student_data)

    return render_template(
        "lecturer_course_students.html",
        course=course,
        students=students
    )

@app.route("/lecturer/students")
def lecturer_students():
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))

    courses = (
        supabase
        .table("courses")
        .select("id, course_code, course_title")
        .eq("lecturer_id", session["user_id"])
        .execute()
        .data
    )

    return render_template("lecturer_students.html", courses=courses)

@app.route("/lecturer/courses/<course_id>/sessions")
def lecturer_course_sessions(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))

    course = get_course_owned_by_lecturer(course_id, session["user_id"])
    if not course:
        return "Unauthorized", 403

    sessions = (
        supabase
        .table("class_sessions")
        .select("*")
        .eq("course_id", course_id)
        .order("created_at", desc=True)
        .execute()
        .data
    )

    active_session = get_active_session(course_id)

    return render_template(
        "lecturer_course_sessions.html",
        course=course,
        sessions=sessions,
        active_session=active_session
    )

@app.route("/lecturer/courses/<course_id>/qr")
def lecturer_qr(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))

    active = get_active_session(course_id)
    if not active:
        return {"error": "No active session"}, 400

    # Get current QR seed
    current_seed = get_current_qr_seed(active["id"])
    
    if not current_seed:
        # Generate initial QR seed if none exists
        current_seed = rotate_qr_seed(active["id"])
    
    return {
        "qr_seed": current_seed,
        "session_id": active["id"],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.route("/lecturer/courses/<course_id>/qr-status")
def qr_status(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return jsonify({"error": "unauthorized"}), 401
    
    active = get_active_session(course_id)
    if not active:
        return jsonify({"error": "No active session"}), 400
    
    # Get current QR info
    resp = (
        supabase
        .table("class_sessions")
        .select("qr_seed, qr_updated_at")
        .eq("id", active["id"])
        .single()
        .execute()
    )
    
    qr_data = resp.data if resp.data else {}
    
    return jsonify({
        "current_qr": qr_data.get("qr_seed"),
        "last_updated": qr_data.get("qr_updated_at"),
        "needs_refresh": not qr_data.get("qr_seed")
    })


# Add this to track QR rotations for debugging
@app.route("/lecturer/courses/<course_id>/qr-history")
def qr_history(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return jsonify({"error": "unauthorized"}), 401
    
    active = get_active_session(course_id)
    if not active:
        return jsonify({"error": "No active session"}), 400
    
    # Get attendance records with timestamps
    attendance_records = (
        supabase
        .table("attendance")
        .select("scanned_at, students(users(full_name, index_number))")
        .eq("session_id", active["id"])
        .order("scanned_at", desc=True)
        .execute()
    )
    
    return jsonify({
        "session_id": active["id"],
        "qr_rotations": len(attendance_records.data) if attendance_records.data else 0,
        "attendance_history": attendance_records.data if attendance_records.data else []
    })

# Fix the start_session function to match your schema
@app.route("/lecturer/courses/<course_id>/start-session", methods=["POST"])
def start_session(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))

    now = datetime.now(timezone.utc)

    # Check for existing active session
    active = get_active_session(course_id)
    if active:
        return jsonify({
            "error": "An active session already exists",
            "session_id": active["id"]
        }), 400

    qr_seed = str(uuid.uuid4())
    
    # FIX: Try both formats to see what works with your database
    # Option 1: Time only (HH:MM:SS)
    # Use time without timezone
    time_only = now.time().isoformat()[:8]  # Gets HH:MM:SS
    
    # Option 2: Full timestamp
    timestamp = now.isoformat()
    
    # Create session data - try time_only first
    insert_data = {
        "course_id": course_id,
        "start_time": time_only,  # Use time format
        "started_at": timestamp,  # Full timestamp
        "is_active": True,
        "qr_seed": qr_seed,
    }
    
    # Create session
    try:
        insert = (
            supabase
            .table("class_sessions")
            .insert(insert_data)
            .execute()
        )
    except Exception as e:
        # If time format fails, try with timestamp
        if "invalid input syntax for type time" in str(e):
            insert_data["start_time"] = timestamp
            insert = (
                supabase
                .table("class_sessions")
                .insert(insert_data)
                .execute()
            )
        else:
            raise e

    return redirect(url_for("lecturer_course_sessions", course_id=course_id))


# Add session extension endpoint
@app.route("/lecturer/courses/<course_id>/extend-session", methods=["POST"])
def extend_session(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))
    
    active = get_active_session(course_id)
    if not active:
        return "No active session", 400
    
    # Extend by 30 minutes
    extension = timedelta(minutes=30)
    new_end_time = datetime.now(timezone.utc) + extension
    
    supabase.table("class_sessions").update({
        "scheduled_end": new_end_time.isoformat(),
        "duration_minutes": active.get("duration_minutes", 180) + 30
    }).eq("id", active["id"]).execute()
    
    return redirect(url_for("lecturer_course_sessions", course_id=course_id))





@app.route("/lecturer/courses/<course_id>/end-session", methods=["POST"])
def end_session(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))
    
    active = get_active_session(course_id)
    if not active:
        return redirect(url_for("lecturer_course_sessions", course_id=course_id))
    
    now = datetime.now(timezone.utc)
    
    supabase.table("class_sessions").update({
        "is_active": False,
        "ended_at": now.isoformat()
    }).eq("id", active["id"]).execute()
    
    return redirect(url_for("lecturer_course_sessions", course_id=course_id))






@app.route("/lecturer/courses/<course_id>/attendance/manual")
def manual_attendance(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))

    lecturer_id = session["user_id"]

    course = get_course_owned_by_lecturer(course_id, lecturer_id)
    if not course:
        return "Unauthorized", 403

    active_session = get_active_session(course_id)
    if not active_session:
        return "No active session", 400

    students = (
        supabase
        .table("course_registration")
        .select(
            "student_id, students(index_number, users(full_name, profile_photo_url))"
        )
        .eq("course_id", course_id)
        .execute()
        .data
    )

    students.sort(key=lambda s: s["students"]["index_number"])

    return render_template(
        "manual_attendance.html",
        course=course,
        session=active_session,
        students=students
    )

@app.route("/lecturer/courses/<course_id>/attendance/manual", methods=["POST"])
def submit_manual_attendance(course_id):
    active_session = get_active_session(course_id)
    if not active_session:
        return "No active session", 400

    for key, value in request.form.items():
        if key.startswith("student_"):
            student_id = key.replace("student_", "")
            supabase.table("attendance").upsert({
                "session_id": active_session["id"],
                "student_id": student_id,
                "status": value
            }).execute()

    return redirect(url_for("lecturer_course_sessions", course_id=course_id))





@app.route("/lecturer/courses/<course_id>/generate-qr", methods=["POST"])
def generate_qr(course_id):
    active = get_active_session(course_id)
    if not active:
        return {"error": "No active session"}, 400

    qr_seed = str(uuid.uuid4())
    expires_at = datetime.now() + timedelta(minutes=5)

    supabase.table("qr_codes").insert({
        "session_id": active["id"],
        "qr_hash": qr_seed,
        "expires_at": expires_at.isoformat()
    }).execute()

    return {
        "qr_hash": qr_seed,
        "expires_at": expires_at.isoformat()
    }, 200

@app.route("/student/courses/<course_id>/qr")
def student_qr(course_id):
    student_id = session.get("user_id")
    if not student_id or session.get("role") != "student":
        return redirect(url_for("login_page"))

    active = get_active_session(course_id)
    if not active:
        return "No active session", 400

    now = datetime.now(timezone.utc)

    existing = (
        supabase
        .table("qr_codes")
        .select("*")
        .eq("session_id", active["id"])
        .eq("student_id", student_id)
        .eq("is_used", False)
        .gt("expires_at", now.isoformat())
        .single()
        .execute()
        .data
    )

    if existing:
        qr_hash = existing["qr_hash"]
        expires_at = existing["expires_at"]
    else:
        qr_hash = str(uuid.uuid4())
        expires_at = (now + timedelta(minutes=5)).isoformat()

        supabase.table("qr_codes").insert({
            "session_id": active["id"],
            "student_id": student_id,
            "qr_hash": qr_hash,
            "qr_seed": active["qr_seed"],
            "expires_at": expires_at,
            "is_used": False
        }).execute()

    return render_template(
        "student_qr.html",
        qr_hash=qr_hash,
        expires_at=expires_at
    )


@app.route("/lecturer/courses/<course_id>/attendance")
def attendance_review(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))

    course = get_course_owned_by_lecturer(course_id, session["user_id"])
    if not course:
        return "Unauthorized", 403

    records = (
        supabase
        .table("attendance")
        .select(
            "scanned_at, status, students(index_number, users(full_name)) , class_sessions(session_date)"
        )
        .eq("class_sessions.course_id", course_id)
        .execute()
        .data
    )

    return render_template(
        "attendance_review.html",
        course=course,
        records=records
    )


# Session Settings Management
@app.route("/lecturer/courses/<course_id>/session-settings", methods=["GET", "POST"])
def session_settings(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))
    
    course = get_course_owned_by_lecturer(course_id, session["user_id"])
    if not course:
        return "Unauthorized", 403
    
    if request.method == "POST":
        # Update session settings
        session_duration = request.form.get("session_duration")
        auto_end = request.form.get("auto_end") == "on"
        allow_late_entry = request.form.get("allow_late_entry") == "on"
        late_entry_minutes = request.form.get("late_entry_minutes", 5)
        
        # Create or update settings
        settings_data = {
            "course_id": course_id,
            "auto_end": auto_end,
            "allow_late_entry": allow_late_entry,
            "late_entry_minutes": int(late_entry_minutes) if late_entry_minutes else 5
        }
        
        if session_duration:
            settings_data["session_duration_minutes"] = int(session_duration)
        
        # Upsert settings
        supabase.table("course_settings").upsert(settings_data).execute()
        
        return redirect(url_for("session_settings", course_id=course_id))
    
    # Get current settings
    try:
        settings = (
            supabase
            .table("course_settings")
            .select("*")
            .eq("course_id", course_id)
            .single()
            .execute()
            .data
        )
    except:
        settings = {
            "session_duration_minutes": 180,  # 3 hours default
            "auto_end": True,
            "allow_late_entry": True,
            "late_entry_minutes": 5
        }
    
    return render_template(
        "session_settings.html",
        course=course,
        settings=settings
    )


# Add validation to attendance scanning for late entries
@app.route("/attendance/scan", methods=["POST"])
def attendance_scan():
    if session.get("role") != "student":
        return jsonify({"error": "unauthorized"}), 401

    student_id = session["user_id"]
    
    # Get QR data
    data = request.get_json() or {}
    qr_seed = data.get("qr_seed")
    
    if not qr_seed:
        return jsonify({"error": "invalid_qr"}), 400

    # Get the active session with current QR seed
    session_row = (
        supabase
        .table("class_sessions")
        .select("id, course_id, started_at, is_active, qr_seed")
        .eq("qr_seed", qr_seed)
        .eq("is_active", True)
        .single()
        .execute()
        .data
    )

    if not session_row:
        return jsonify({"error": "expired_or_invalid"}), 400
    
    # Verify the QR seed matches exactly
    if session_row.get("qr_seed") != qr_seed:
        return jsonify({"error": "qr_expired"}), 400
    
    # Check session age (existing code remains)
    started_at = datetime.fromisoformat(
        session_row["started_at"].replace("Z", "+00:00")
    )
    now = datetime.now(timezone.utc)
    session_age = now - started_at
    
    # Get course settings for late entry policy (existing code remains)
    try:
        settings = (
            supabase
            .table("course_settings")
            .select("allow_late_entry, late_entry_minutes")
            .eq("course_id", session_row["course_id"])
            .single()
            .execute()
            .data
        )
        
        allow_late_entry = settings.get("allow_late_entry", True)
        late_entry_minutes = settings.get("late_entry_minutes", 5)
    except:
        allow_late_entry = True
        late_entry_minutes = 5
    
    # Check if student is too late (existing code remains)
    late_entry_duration = timedelta(minutes=late_entry_minutes)
    if session_age > late_entry_duration and not allow_late_entry:
        return jsonify({
            "error": "too_late",
            "message": f"Session closed for late entry. Maximum late entry: {late_entry_minutes} minutes."
        }), 400
    
    # Check if student is registered for this course (existing code remains)
    registration_check = (
        supabase
        .table("course_registration")
        .select("*")
        .eq("course_id", session_row["course_id"])
        .eq("student_id", student_id)
        .single()
        .execute()
        .data
    )

    if not registration_check:
        return jsonify({"error": "not_registered"}), 403

    # Check if already attended this session (existing code remains)
    existing_attendance = (
        supabase
        .table("attendance")
        .select("*")
        .eq("session_id", session_row["id"])
        .eq("student_id", student_id)
        .single()
        .execute()
        .data
    )

    if existing_attendance:
        return jsonify({"error": "already_scanned"}), 400
    
    # Mark attendance status based on timing (existing code remains)
    if session_age > timedelta(minutes=late_entry_minutes):
        status = "late"
        late_by = int((session_age - timedelta(minutes=late_entry_minutes)).total_seconds() / 60)
    else:
        status = "present"
        late_by = 0
    
    # Record attendance (existing code remains)
    attendance_data = {
        "session_id": session_row["id"],
        "student_id": student_id,
        "status": status,
        "scanned_at": now.isoformat(),
        "was_late": late_by > 0,
        "minutes_late": late_by
    }
    
    supabase.table("attendance").insert(attendance_data).execute()

    # ROTATE QR SEED IMMEDIATELY AFTER SUCCESSFUL SCAN
    new_qr_seed = rotate_qr_seed(session_row["id"])
    
    if not new_qr_seed:
        return jsonify({"error": "qr_rotation_failed"}), 500

    # Get student details for confirmation (existing code remains)
    student = (
        supabase
        .table("students")
        .select("index_number, users(full_name, profile_photo_url)")
        .eq("user_id", student_id)
        .single()
        .execute()
        .data
    )

    return jsonify({
        "success": True,
        "name": student["users"]["full_name"],
        "index_number": student["index_number"],
        "photo": student["users"]["profile_photo_url"],
        "session_id": session_row["id"],
        "course_id": session_row["course_id"],
        "status": status,
        "late_by": late_by,
        "qr_rotated": True,  # Inform frontend that QR was rotated
        "message": "Attendance marked successfully! QR code has been rotated." + 
                  (f" Marked as late ({late_by} minutes late)." if late_by > 0 else "")
    })

@app.route("/student/attendance/recent")
def recent_attendance():
    if session.get("role") != "student":
        return jsonify({"error": "unauthorized"}), 401
    
    student_id = session["user_id"]
    
    # Get recent attendance records (last 10)
    records = (
        supabase
        .table("attendance")
        .select("""
            scanned_at,
            status,
            class_sessions(
                courses(course_code, course_title)
            )
        """)
        .eq("student_id", student_id)
        .order("scanned_at", desc=True)
        .limit(10)
        .execute()
        .data
    )
    
    return jsonify(records)

@app.route("/lecturer/attendance")
def lecturer_attendance():
    return render_template("lecturer_attendance.html")

@app.route("/lecturer/chat")
def lecturer_chat():
    return render_template("lecturer_chat.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/student/dashboard")
def student_dashboard():
    if "user_id" not in session or session.get("role") != "student":
        return redirect(url_for("student_login"))

    # Get student profile with user info
    profile_data = (
        supabase
        .table("students")
        .select(
            "index_number, programme, level, department, users!inner(full_name, email)"
        )
        .eq("user_id", session["user_id"])
        .single()
        .execute()
    )

    if not profile_data.data:
        session.clear()
        return redirect(url_for("student_login"))

    profile = profile_data.data
    
    # Get registered courses for the dashboard stats
    registered_courses = (
        supabase
        .table("course_registration")
        .select(
            """
            id,
            courses(
                id,
                course_code,
                course_title
            )
            """
        )
        .eq("student_id", session["user_id"])
        .execute()
        .data
    )

    return render_template(
        "student_dashboard.html",
        profile=profile,
        registered_courses=registered_courses
    )

@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    if request.method == "GET":
        return render_template("student_login.html")
    
    identifier = request.form.get("identifier")
    password = request.form.get("password")
    
    user = authenticate_user(identifier, password)
    
    if not user:
        return render_template("student_login.html", error="Invalid email or password")
    
    if user["role"] != "student":
        return render_template("student_login.html", error="Access denied. Student login only.")
    
    # Store user info in session
    session["user_id"] = user["id"]
    session["role"] = user["role"]
    session["full_name"] = user["full_name"]
    session["email"] = user["email"]
    
    # For students, also store index_number
    if "index_number" in user:
        session["index_number"] = user["index_number"]
    
    return redirect("/student/dashboard")


@app.route("/lecturer/courses/<course_id>/live-attendance")
def lecturer_live_attendance(course_id):
    if session.get("role") != "lecturer":
        return redirect(url_for("login_page"))

    course = get_course_owned_by_lecturer(course_id, session["user_id"])
    if not course:
        return "Unauthorized", 403

    active_session = get_active_session(course_id)
    if not active_session:
        return redirect(
            url_for("lecturer_course_sessions", course_id=course_id)
        )

    return render_template(
        "lecturer_live_attendance.html",
        course=course,
        active_session=active_session
    )


@app.route("/lecturer/courses/<course_id>/live-attendance/poll")
def live_attendance_poll(course_id):
    if session.get("role") != "lecturer":
        return jsonify([])

    active = get_active_session(course_id)
    if not active:
        return jsonify([])

    records = (
        supabase
        .table("attendance")
        .select(
            "scanned_at, students(index_number, users(full_name, profile_photo_url))"
        )
        .eq("session_id", active["id"])
        .order("scanned_at", desc=True)
        .execute()
        .data
    )

    return jsonify(records)


@app.route("/student/attendance")
def student_attendance_history():
    if session.get("role") != "student":
        return redirect("/student/login")

    records = (
        supabase
        .table("attendance")
        .select("""
            scanned_at,
            status,
            class_sessions(
                courses(course_code, course_title)
            )
        """)
        .eq("student_id", session["user_id"])
        .execute()
        .data
    )

    return render_template(
        "student_attendance.html",
        records=records
    )

@app.route("/student/scan")
def student_scan_page():
    if session.get("role") != "student":
        return redirect("/student/login")

    return render_template("student_scan.html")

# Add this route for viewing registered courses


@app.route("/student/my-courses")
def student_my_courses():
    if session.get("role") != "student":
        return redirect("/student/login")
    
    student_id = session["user_id"]
    
    # Get all registered courses with details
    registered_courses = (
        supabase
        .table("course_registration")
        .select(
            """
            id,
            registered_at,
            courses(
                id,
                course_code,
                course_title,
                academic_year,
                semester,
                lecturers(
                    users(full_name, profile_photo_url)
                )
            )
            """
        )
        .eq("student_id", student_id)
        .order("registered_at", desc=True)
        .execute()
        .data
    )
    
    return render_template(
        "student_my_courses.html",
        registered_courses=registered_courses
    )

# Add this route for deleting a registered course
@app.route("/student/unregister-course/<registration_id>", methods=["POST"])
def unregister_course(registration_id):
    if session.get("role") != "student":
        return redirect("/student/login")
    
    student_id = session["user_id"]
    
    # First verify this registration belongs to the student
    registration = (
        supabase
        .table("course_registration")
        .select("*")
        .eq("id", registration_id)
        .eq("student_id", student_id)
        .single()
        .execute()
        .data
    )
    
    if not registration:
        return "Unauthorized", 403
    
    # Delete the registration
    supabase.table("course_registration").delete().eq("id", registration_id).execute()
    
    return redirect("/student/my-courses")

@app.route("/student/browse-courses")
def student_browse_courses():
    if session.get("role") != "student":
        return redirect("/student/login")
    
    student_id = session["user_id"]
    
    # Get ALL courses from the database
    courses = (
        supabase
        .table("courses")
        .select("""
            id,
            course_code,
            course_title,
            academic_year,
            semester,
            lecturers(
                users(full_name)
            )
        """)
        .order("course_code")
        .execute()
        .data
    )
    
    # Get the student's registered course IDs
    registered = (
        supabase
        .table("course_registration")
        .select("course_id")
        .eq("student_id", student_id)
        .execute()
        .data
    )
    
    registered_ids = {r["course_id"] for r in registered}
    
    # Add registration status to each course
    for course in courses:
        course["is_registered"] = course["id"] in registered_ids
    
    # Search functionality
    search_query = request.args.get('q', '').strip()
    if search_query:
        search_lower = search_query.lower()
        courses = [
            course for course in courses
            if (search_lower in course["course_code"].lower() or 
                search_lower in course["course_title"].lower())
        ]
    
    return render_template(
        "student_browse_courses.html",
        courses=courses,
        search_query=search_query
    )

@app.route("/student/register", methods=["GET", "POST"])
def student_register():
    if request.method == "GET":
        return render_template("student_register.html")
    
    try:
        # Get form data with defaults
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        full_name = request.form.get("full_name", "").strip()
        index_number = request.form.get("index_number", "").strip()
        programme = request.form.get("programme", "").strip()
        level_str = request.form.get("level", "").strip()
        department = request.form.get("department", "").strip()
        
        # Validate required fields
        if not all([email, password, full_name, index_number, programme, level_str, department]):
            return render_template("student_register.html", 
                                 error="Please fill in all required fields")
        
        try:
            level = int(level_str)
        except ValueError:
            return render_template("student_register.html", 
                                 error="Please select a valid level")
        
        # Check if email already exists
        existing_user = (
            supabase
            .table("users")
            .select("id")
            .eq("email", email)
            .execute()
        )
        
        if existing_user.data:
            return render_template("student_register.html", 
                                 error="Email already registered. Please use a different email.")
        
        # Check if index number already exists
        existing_student = (
            supabase
            .table("students")
            .select("index_number")
            .eq("index_number", index_number)
            .execute()
        )
        
        if existing_student.data:
            return render_template("student_register.html", 
                                 error="Index number already registered. Please check your details.")
        
        # Handle passport photo upload to Supabase Storage
        profile_photo_url = None
        if 'passport_photo' in request.files:
            file = request.files['passport_photo']
            if file and file.filename != '':
                # Check file extension
                if not allowed_file(file.filename):
                    return render_template("student_register.html", 
                                         error="Invalid file type. Please upload PNG, JPG, or JPEG only.")
                
                # Check file size
                file.seek(0, 2)  # Seek to end
                file_size = file.tell()  # Get file size
                file.seek(0)  # Reset file pointer
                
                if file_size > app.config['MAX_CONTENT_LENGTH']:
                    return render_template("student_register.html", 
                                         error="File too large. Maximum size is 2MB.")
                
                # Generate unique filename
                filename = secure_filename(f"{index_number}_{uuid.uuid4().hex[:8]}_{file.filename}")
                
                # Upload to Supabase Storage - profile-photos bucket (public)
                try:
                    # Read file content
                    file_content = file.read()
                    
                    # Upload to Supabase Storage
                    upload_response = supabase.storage.from_("profile-photos").upload(
                        path=filename,
                        file=file_content,
                        file_options={"content-type": file.content_type}
                    )
                    
                    if upload_response:
                        # Get public URL
                        profile_photo_url = supabase.storage.from_("profile-photos").get_public_url(filename)
                    else:
                        print("Upload failed or returned None")
                        
                except Exception as upload_error:
                    print(f"Error uploading to Supabase Storage: {upload_error}")
                    return render_template("student_register.html", 
                                         error="Failed to upload profile photo. Please try again.")
        
        # Generate user ID and hash password
        user_id = str(uuid.uuid4())
        password_hash = generate_password_hash(password)

        # Prepare user data
        user_data = {
            "id": user_id,
            "email": email,
            "password_hash": password_hash,
            "full_name": full_name,
            "role": "student"
        }
        
        if profile_photo_url:
            user_data["profile_photo_url"] = profile_photo_url
        
        # Insert into users table
        user_result = supabase.table("users").insert(user_data).execute()
        
        if not user_result.data:
            # If user creation fails, also delete the uploaded file
            if profile_photo_url:
                try:
                    supabase.storage.from_("profile-photos").remove([filename])
                except:
                    pass
            return render_template("student_register.html", 
                                 error="Failed to create user account. Please try again.")
        
        # Insert into students table
        student_data = {
            "user_id": user_id,
            "index_number": index_number,
            "programme": programme,
            "level": level,
            "department": department
        }
        
        student_result = supabase.table("students").insert(student_data).execute()
        
        if not student_result.data:
            # Rollback user creation and file upload if student creation fails
            supabase.table("users").delete().eq("id", user_id).execute()
            if profile_photo_url:
                try:
                    supabase.storage.from_("profile-photos").remove([filename])
                except:
                    pass
            return render_template("student_register.html", 
                                 error="Failed to create student profile. Please try again.")
        
        # Registration successful - redirect to login page
        return redirect("/student/login?registered=true")
        
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return render_template("student_register.html", 
                             error=f"Registration failed: {str(e)}")

        # Add this route to check if student has already attended current session
@app.route("/student/attendance/check-session")
def check_current_session():
    if session.get("role") != "student":
        return jsonify({"error": "unauthorized"}), 401
    
    student_id = session["user_id"]
    
    # Get student's registered course IDs
    registered_courses = (
        supabase
        .table("course_registration")
        .select("course_id")
        .eq("student_id", student_id)
        .execute()
        .data
    )
    
    if not registered_courses:
        return jsonify({"has_active_session": False})
    
    course_ids = [reg["course_id"] for reg in registered_courses]
    
    # Check for active sessions in any of the student's courses
    active_sessions = (
        supabase
        .table("class_sessions")
        .select("id, course_id, started_at")
        .eq("is_active", True)
        .in_("course_id", course_ids)
        .execute()
        .data
    )
    
    if not active_sessions:
        return jsonify({"has_active_session": False})
    
    # Check if student has already attended any active session
    session_ids = [session["id"] for session in active_sessions]
    
    existing_attendance = (
        supabase
        .table("attendance")
        .select("session_id")
        .eq("student_id", student_id)
        .in_("session_id", session_ids)
        .execute()
        .data
    )
    
    if existing_attendance:
        return jsonify({
            "has_active_session": True,
            "already_attended": True,
            "session_id": existing_attendance[0]["session_id"]
        })
    
    return jsonify({
        "has_active_session": True,
        "already_attended": False,
        "sessions": active_sessions
    })

# Add this route to get QR code data for lecturer page
@app.route("/lecturer/courses/<course_id>/qr-data")
def get_qr_data(course_id):
    if session.get("role") != "lecturer":
        return jsonify({"error": "unauthorized"}), 401
    
    active = get_active_session(course_id)
    if not active:
        return jsonify({"error": "No active session"}), 400
    
    # Get attendance count for this session
    attendance_count = (
        supabase
        .table("attendance")
        .select("*", count="exact")
        .eq("session_id", active["id"])
        .execute()
    )
    
    count = attendance_count.count if hasattr(attendance_count, 'count') else len(attendance_count.data)
    
    return jsonify({
        "qr_seed": active["qr_seed"],
        "session_start": active["started_at"],
        "attendance_count": count,
        "session_id": active["id"]
    })


# Add API endpoints for the frontend
@app.route("/api/courses/total-students")
def api_total_students():
    if "user_id" not in session or session.get("role") != "lecturer":
        return jsonify({"error": "unauthorized"}), 401
    
    lecturer_id = session["user_id"]
    
    # Get lecturer's courses
    courses = (
        supabase
        .table("courses")
        .select("id")
        .eq("lecturer_id", lecturer_id)
        .execute()
        .data
    )
    
    if not courses:
        return jsonify({"totalStudents": 0})
    
    course_ids = [course["id"] for course in courses]
    
    # Count unique students across all courses
    students_query = (
        supabase
        .table("course_registration")
        .select("student_id", count="exact")
        .in_("course_id", course_ids)
        .execute()
    )
    
    total_students = students_query.count if hasattr(students_query, 'count') else len(students_query.data)
    
    return jsonify({"totalStudents": total_students})

@app.route("/api/courses/<course_id>/student-count")
def api_course_student_count(course_id):
    if "user_id" not in session or session.get("role") != "lecturer":
        return jsonify({"error": "unauthorized"}), 401
    
    # Verify lecturer owns this course
    course = get_course_owned_by_lecturer(course_id, session["user_id"])
    if not course:
        return jsonify({"error": "unauthorized"}), 403
    
    # Count students registered for this course
    students_query = (
        supabase
        .table("course_registration")
        .select("*", count="exact")
        .eq("course_id", course_id)
        .execute()
    )
    
    count = students_query.count if hasattr(students_query, 'count') else len(students_query.data)
    
    return jsonify({"count": count})

@app.route("/api/active-sessions")
def api_active_sessions():
    if "user_id" not in session or session.get("role") != "lecturer":
        return jsonify({"error": "unauthorized"}), 401
    
    lecturer_id = session["user_id"]
    
    # Get lecturer's courses
    courses = (
        supabase
        .table("courses")
        .select("id")
        .eq("lecturer_id", lecturer_id)
        .execute()
        .data
    )
    
    if not courses:
        return jsonify({"count": 0})
    
    course_ids = [course["id"] for course in courses]
    
    # Count active sessions for lecturer's courses
    sessions_query = (
        supabase
        .table("class_sessions")
        .select("*", count="exact")
        .eq("is_active", True)
        .in_("course_id", course_ids)
        .execute()
    )
    
    count = sessions_query.count if hasattr(sessions_query, 'count') else len(sessions_query.data)
    
    return jsonify({"count": count})


# Add these template filters after the existing format_datetime function

@app.template_filter('parse_datetime')
def parse_datetime(value):
    """Parse datetime string to datetime object"""
    if not value:
        return None
    try:
        if 'Z' in value:
            value = value.replace('Z', '+00:00')
        return datetime.fromisoformat(value)
    except (ValueError, AttributeError):
        return None

# Add these template filters and context processors AFTER your existing format_datetime function

# Template filter for calculating duration
@app.template_filter('calculate_duration')
def calculate_duration(start_str, end_str):
    """Calculate duration between two datetime strings"""
    try:
        if not start_str or not end_str:
            return "Unknown"
            
        # Parse the datetime strings
        if 'Z' in start_str:
            start_str = start_str.replace('Z', '+00:00')
        if 'Z' in end_str:
            end_str = end_str.replace('Z', '+00:00')
            
        start = datetime.fromisoformat(start_str)
        end = datetime.fromisoformat(end_str)
        
        # Calculate duration
        duration = end - start
        total_seconds = int(duration.total_seconds())
        
        # Format as hours and minutes
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        elif minutes > 0:
            return f"{minutes}m"
        else:
            seconds = total_seconds % 60
            return f"{seconds}s"
            
    except Exception as e:
        print(f"Error calculating duration: {e}")
        return "Unknown"

# Template filter to get attendance count
@app.template_filter('get_attendance_count')
def get_attendance_count(session_id):
    """Get attendance count for a session"""
    try:
        attendance = (
            supabase
            .table("attendance")
            .select("*", count="exact")
            .eq("session_id", session_id)
            .execute()
        )
        return attendance.count if hasattr(attendance, 'count') else len(attendance.data)
    except:
        return 0

# =================== CHAT SYSTEM ROUTES (UPDATED) ===================

@app.route("/lecturer/chat")
def lecturer_chat_main():
    if "user_id" not in session or session.get("role") != "lecturer":
        return redirect(url_for("login_page"))
    
    lecturer_id = session["user_id"]
    
    # Get lecturer's courses from database
    courses_response = (
        supabase
        .table("courses")
        .select("id, course_code, course_title")
        .eq("lecturer_id", lecturer_id)
        .execute()
    )
    
    courses = courses_response.data if courses_response.data else []
    
    # Get lecturer's chat threads from database
    try:
        threads_response = supabase.rpc('get_lecturer_threads', {
            'lecturer_id': lecturer_id
        }).execute()
        threads = threads_response.data if threads_response.data else []
    except:
        # Fallback query if RPC function doesn't exist yet
        threads_response = (
            supabase
            .from_('chat_threads')
            .select('''
                id,
                thread_name,
                thread_type,
                course_id,
                courses!inner(
                    course_code,
                    course_title
                ),
                last_message_at,
                chat_messages(
                    message_text,
                    sender_id,
                    sent_at,
                    message_type,
                    users!chat_messages_sender_id_fkey(
                        full_name
                    )
                )
            ''')
            .eq('courses.lecturer_id', lecturer_id)
            .order('last_message_at', desc=True)
            .limit(20)
            .execute()
        )
        threads = threads_response.data if threads_response.data else []
    
    # Get lecturer's user info from session
    user_info = {
        "full_name": session.get("full_name", "Lecturer"),
        "index_number": None,  # Lecturers don't have index numbers
        "role": "lecturer"
    }
    
    return render_template(
        "lecturer_chat.html",
        courses=courses,
        threads=threads,
        user_id=lecturer_id,
        current_user=user_info  # Pass user info to template
    )

@app.route("/student/chat")
def student_chat_main():
    if "user_id" not in session or session.get("role") != "student":
        return redirect(url_for("student_login"))
    
    student_id = session["user_id"]
    
    # Get student's registered courses from database
    registered_courses_response = (
        supabase
        .table("course_registration")
        .select('''
            courses(
                id,
                course_code,
                course_title,
                lecturers(
                    users(
                        full_name
                    )
                )
            )
        ''')
        .eq("student_id", student_id)
        .execute()
    )
    
    registered_courses = registered_courses_response.data if registered_courses_response.data else []
    
    # Get student's chat threads from database
    try:
        threads_response = supabase.rpc('get_student_threads', {
            'student_id': student_id
        }).execute()
        threads = threads_response.data if threads_response.data else []
    except:
        # Fallback query
        threads_response = (
            supabase
            .from_('chat_participants')
            .select('''
                chat_threads(
                    id,
                    thread_name,
                    thread_type,
                    course_id,
                    courses(
                        course_code,
                        course_title
                    ),
                    last_message_at
                )
            ''')
            .eq('user_id', student_id)
            .execute()
        )
        threads = [t['chat_threads'] for t in (threads_response.data if threads_response.data else [])]
    
    # Get student's user info from session
    user_info = {
        "full_name": session.get("full_name", "Student"),
        "index_number": session.get("index_number", "N/A"),
        "role": "student"
    }
    
    return render_template(
        "student_chat.html",
        courses=[rc['courses'] for rc in registered_courses],
        threads=threads,
        user_id=student_id,
        current_user=user_info  # Pass user info to template
    )

# Add the missing RPC functions to your database:
RPC_FUNCTIONS = """
-- Get lecturer's threads
CREATE OR REPLACE FUNCTION get_lecturer_threads(lecturer_id UUID)
RETURNS TABLE(
    id UUID,
    thread_name TEXT,
    thread_type VARCHAR,
    course_id UUID,
    course_code TEXT,
    course_title TEXT,
    last_message_at TIMESTAMPTZ,
    last_message TEXT,
    sender_name TEXT,
    unread_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ct.id,
        ct.thread_name,
        ct.thread_type,
        ct.course_id,
        c.course_code,
        c.course_title,
        ct.last_message_at,
        (
            SELECT cm.message_text 
            FROM chat_messages cm
            WHERE cm.thread_id = ct.id
            ORDER BY cm.sent_at DESC
            LIMIT 1
        ) as last_message,
        (
            SELECT u.full_name 
            FROM chat_messages cm2
            LEFT JOIN users u ON cm2.sender_id = u.id
            WHERE cm2.thread_id = ct.id
            ORDER BY cm2.sent_at DESC
            LIMIT 1
        ) as sender_name,
        (
            SELECT COUNT(*) 
            FROM chat_messages cm3
            WHERE cm3.thread_id = ct.id
            AND cm3.is_read = FALSE
            AND cm3.sender_id != lecturer_id
        ) as unread_count
    FROM chat_threads ct
    LEFT JOIN courses c ON ct.course_id = c.id
    WHERE (
        ct.thread_type = 'course' 
        AND c.lecturer_id = lecturer_id
    )
    OR ct.created_by = lecturer_id
    OR ct.id IN (
        SELECT thread_id 
        FROM chat_participants 
        WHERE user_id = lecturer_id
    )
    ORDER BY ct.last_message_at DESC;
END;
$$ LANGUAGE plpgsql;

-- Get student's threads
CREATE OR REPLACE FUNCTION get_student_threads(student_id UUID)
RETURNS TABLE(
    id UUID,
    thread_name TEXT,
    thread_type VARCHAR,
    course_id UUID,
    course_code TEXT,
    course_title TEXT,
    last_message_at TIMESTAMPTZ,
    last_message TEXT,
    sender_name TEXT,
    unread_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ct.id,
        ct.thread_name,
        ct.thread_type,
        ct.course_id,
        c.course_code,
        c.course_title,
        ct.last_message_at,
        (
            SELECT cm.message_text 
            FROM chat_messages cm
            WHERE cm.thread_id = ct.id
            ORDER BY cm.sent_at DESC
            LIMIT 1
        ) as last_message,
        (
            SELECT u.full_name 
            FROM chat_messages cm2
            LEFT JOIN users u ON cm2.sender_id = u.id
            WHERE cm2.thread_id = ct.id
            ORDER BY cm2.sent_at DESC
            LIMIT 1
        ) as sender_name,
        (
            SELECT COUNT(*) 
            FROM chat_messages cm3
            WHERE cm3.thread_id = ct.id
            AND cm3.is_read = FALSE
            AND cm3.sender_id != student_id
        ) as unread_count
    FROM chat_threads ct
    LEFT JOIN courses c ON ct.course_id = c.id
    WHERE ct.id IN (
        SELECT thread_id 
        FROM chat_participants 
        WHERE user_id = student_id
    )
    ORDER BY ct.last_message_at DESC;
END;
$$ LANGUAGE plpgsql;

-- Get course chats for student
CREATE OR REPLACE FUNCTION get_student_course_chats(student_id UUID)
RETURNS TABLE(
    course_id UUID,
    course_code TEXT,
    course_title TEXT,
    thread_id UUID,
    unread_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.id as course_id,
        c.course_code,
        c.course_title,
        ct.id as thread_id,
        (
            SELECT COUNT(*) 
            FROM chat_messages cm
            JOIN chat_participants cp ON cm.thread_id = cp.thread_id
            WHERE cm.thread_id = ct.id
            AND cm.is_read = FALSE
            AND cm.sender_id != student_id
            AND cp.user_id = student_id
        ) as unread_count
    FROM courses c
    LEFT JOIN chat_threads ct ON c.id = ct.course_id AND ct.thread_type = 'course'
    WHERE c.id IN (
        SELECT course_id 
        FROM course_registration 
        WHERE student_id = student_id
    )
    ORDER BY c.course_code;
END;
$$ LANGUAGE plpgsql;

-- Get lecturers for student
CREATE OR REPLACE FUNCTION get_student_lecturers(student_id UUID)
RETURNS TABLE(
    id UUID,
    full_name TEXT,
    title TEXT,
    email TEXT,
    course_code TEXT,
    course_title TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT
        u.id,
        u.full_name,
        l.title,
        u.email,
        c.course_code,
        c.course_title
    FROM users u
    JOIN lecturers l ON u.id = l.user_id
    JOIN courses c ON l.user_id = c.lecturer_id
    WHERE c.id IN (
        SELECT course_id 
        FROM course_registration 
        WHERE student_id = student_id
    )
    ORDER BY u.full_name;
END;
$$ LANGUAGE plpgsql;

-- Get classmates for student
CREATE OR REPLACE FUNCTION get_student_classmates(student_id UUID)
RETURNS TABLE(
    id UUID,
    full_name TEXT,
    index_number TEXT,
    programme TEXT,
    level INTEGER,
    profile_photo_url TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT
        u.id,
        u.full_name,
        s.index_number,
        s.programme,
        s.level,
        u.profile_photo_url
    FROM users u
    JOIN students s ON u.id = s.user_id
    WHERE s.user_id IN (
        SELECT cr2.student_id
        FROM course_registration cr1
        JOIN course_registration cr2 ON cr1.course_id = cr2.course_id
        WHERE cr1.student_id = student_id
        AND cr2.student_id != student_id
    )
    ORDER BY u.full_name;
END;
$$ LANGUAGE plpgsql;
"""

# Now update the API endpoints:

@app.route("/api/chat/student/threads")
def get_student_threads_api():
    if "user_id" not in session or session.get("role") != "student":
        return jsonify({"error": "unauthorized"}), 401
    
    student_id = session["user_id"]
    
    try:
        threads_response = supabase.rpc('get_student_threads', {
            'student_id': student_id
        }).execute()
        threads = threads_response.data if threads_response.data else []
        
        return jsonify(threads)
        
    except Exception as e:
        print(f"Error getting student threads: {e}")
        return jsonify({"error": "database_error"}), 500

@app.route("/api/chat/lecturer/threads")
def get_lecturer_threads_api():
    if "user_id" not in session or session.get("role") != "lecturer":
        return jsonify({"error": "unauthorized"}), 401
    
    lecturer_id = session["user_id"]
    
    try:
        threads_response = supabase.rpc('get_lecturer_threads', {
            'lecturer_id': lecturer_id
        }).execute()
        threads = threads_response.data if threads_response.data else []
        
        return jsonify(threads)
        
    except Exception as e:
        print(f"Error getting lecturer threads: {e}")
        return jsonify({"error": "database_error"}), 500

@app.route("/api/chat/student/course-chats")
def get_student_course_chats_api():
    if "user_id" not in session or session.get("role") != "student":
        return jsonify({"error": "unauthorized"}), 401
    
    student_id = session["user_id"]
    
    try:
        course_chats_response = supabase.rpc('get_student_course_chats', {
            'student_id': student_id
        }).execute()
        course_chats = course_chats_response.data if course_chats_response.data else []
        
        return jsonify(course_chats)
        
    except Exception as e:
        print(f"Error getting course chats: {e}")
        return jsonify({"error": "database_error"}), 500

@app.route("/api/chat/student/lecturers")
def get_student_lecturers_api():
    if "user_id" not in session or session.get("role") != "student":
        return jsonify({"error": "unauthorized"}), 401
    
    student_id = session["user_id"]
    
    try:
        lecturers_response = supabase.rpc('get_student_lecturers', {
            'student_id': student_id
        }).execute()
        lecturers = lecturers_response.data if lecturers_response.data else []
        
        return jsonify(lecturers)
        
    except Exception as e:
        print(f"Error getting lecturers: {e}")
        return jsonify({"error": "database_error"}), 500

@app.route("/api/chat/student/classmates")
def get_student_classmates_api():
    if "user_id" not in session or session.get("role") != "student":
        return jsonify({"error": "unauthorized"}), 401
    
    student_id = session["user_id"]
    
    try:
        classmates_response = supabase.rpc('get_student_classmates', {
            'student_id': student_id
        }).execute()
        classmates = classmates_response.data if classmates_response.data else []
        
        return jsonify(classmates)
        
    except Exception as e:
        print(f"Error getting classmates: {e}")
        return jsonify({"error": "database_error"}), 500

@app.route("/api/chat/lecturer/students")
def get_lecturer_students_api():
    if "user_id" not in session or session.get("role") != "lecturer":
        return jsonify({"error": "unauthorized"}), 401
    
    lecturer_id = session["user_id"]
    
    try:
        # Get lecturer's courses
        courses_response = (
            supabase
            .table("courses")
            .select("id")
            .eq("lecturer_id", lecturer_id)
            .execute()
        )
        
        if not courses_response.data:
            return jsonify([])
        
        course_ids = [course["id"] for course in courses_response.data]
        
        # Get students from these courses
        students_response = (
            supabase
            .from_('course_registration')
            .select('''
                student_id,
                students!inner(
                    index_number,
                    programme,
                    level,
                    users!inner(
                        id,
                        full_name,
                        email,
                        profile_photo_url
                    )
                )
            ''')
            .in_('course_id', course_ids)
            .execute()
        )
        
        if not students_response.data:
            return jsonify([])
        
        # Process the data
        students = []
        seen_ids = set()
        
        for reg in students_response.data:
            student = reg.get('students')
            if student and student.get('users'):
                user_data = student['users']
                student_id = user_data['id']
                
                if student_id not in seen_ids:
                    seen_ids.add(student_id)
                    students.append({
                        'id': student_id,
                        'full_name': user_data['full_name'],
                        'email': user_data['email'],
                        'index_number': student['index_number'],
                        'programme': student['programme'],
                        'level': student['level'],
                        'profile_photo_url': user_data['profile_photo_url']
                    })
        
        return jsonify(students)
        
    except Exception as e:
        print(f"Error getting lecturer's students: {e}")
        return jsonify({"error": "database_error"}), 500

@app.route("/api/chat/thread/<thread_id>/info")
def get_thread_info(thread_id):
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    try:
        # Get thread info with participants
        thread_response = (
            supabase
            .table("chat_threads")
            .select('''
                id,
                thread_name,
                thread_type,
                course_id,
                created_at,
                chat_participants(
                    user_id,
                    users!inner(
                        full_name,
                        profile_photo_url
                    )
                )
            ''')
            .eq("id", thread_id)
            .single()
            .execute()
        )
        
        if not thread_response.data:
            return jsonify({"error": "thread_not_found"}), 404
        
        thread = thread_response.data
        
        # Check if user has access
        user_id = session["user_id"]
        is_participant = any(
            participant['user_id'] == user_id 
            for participant in thread.get('chat_participants', [])
        )
        
        if not is_participant and session.get("role") == "student":
            # Students can only access threads they're in
            return jsonify({"error": "access_denied"}), 403
        
        # Format the response
        participants = []
        for participant in thread.get('chat_participants', []):
            if participant.get('users'):
                participants.append({
                    'id': participant['user_id'],
                    'full_name': participant['users']['full_name'],
                    'profile_photo_url': participant['users']['profile_photo_url']
                })
        
        response_data = {
            'id': thread['id'],
            'thread_name': thread['thread_name'],
            'thread_type': thread['thread_type'],
            'course_id': thread['course_id'],
            'created_at': thread['created_at'],
            'participants': participants,
            'participants_count': len(participants)
        }
        
        # Add course info if it's a course chat
        if thread['course_id']:
            course_response = (
                supabase
                .table("courses")
                .select("course_code, course_title")
                .eq("id", thread['course_id'])
                .single()
                .execute()
            )
            
            if course_response.data:
                response_data['course_code'] = course_response.data['course_code']
                response_data['course_title'] = course_response.data['course_title']
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"Error getting thread info: {e}")
        return jsonify({"error": "database_error"}), 500

@app.route("/api/chat/thread/<thread_id>/messages")
def get_thread_messages_api(thread_id):
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    user_id = session["user_id"]
    
    # Verify user has access to this thread
    try:
        participant_response = (
            supabase
            .table("chat_participants")
            .select("*")
            .eq("thread_id", thread_id)
            .eq("user_id", user_id)
            .execute()
        )
        
        if not participant_response.data and session.get("role") == "student":
            return jsonify({"error": "access_denied"}), 403
        
        # For lecturers, check if they own the course
        if session.get("role") == "lecturer" and not participant_response.data:
            thread_response = (
                supabase
                .table("chat_threads")
                .select("course_id")
                .eq("id", thread_id)
                .single()
                .execute()
            )
            
            if thread_response.data:
                course_id = thread_response.data['course_id']
                if course_id:
                    course_response = (
                        supabase
                        .table("courses")
                        .select("lecturer_id")
                        .eq("id", course_id)
                        .single()
                        .execute()
                    )
                    
                    if not course_response.data or course_response.data['lecturer_id'] != user_id:
                        return jsonify({"error": "access_denied"}), 403
        
    except Exception as e:
        print(f"Error checking access: {e}")
        return jsonify({"error": "access_check_failed"}), 500
    
    try:
        # Get messages with user info
        messages_response = (
            supabase
            .from_('chat_messages')
            .select('''
                id,
                message_text,
                message_type,
                image_url,
                file_name,
                file_size,
                audio_duration,
                thumbnail_url,
                sender_id,
                users!chat_messages_sender_id_fkey(
                    full_name,
                    profile_photo_url
                ),
                sent_at,
                is_read
            ''')
            .eq('thread_id', thread_id)
            .order('sent_at', desc=True)
            .limit(50)
            .execute()
        )
        
        messages = messages_response.data if messages_response.data else []
        
        # Mark messages as read (except user's own messages)
        if messages:
            unread_message_ids = [
                msg['id'] for msg in messages 
                if not msg['is_read'] and msg['sender_id'] != user_id
            ]
            
            if unread_message_ids:
                supabase.table("chat_messages").update({
                    "is_read": True,
                    "read_at": datetime.now(timezone.utc).isoformat()
                }).in_("id", unread_message_ids).execute()
        
        return jsonify(messages)
        
    except Exception as e:
        print(f"Error getting messages: {e}")
        return jsonify({"error": "database_error"}), 500

@app.route("/api/chat/thread/create", methods=["POST"])
def create_chat_thread_api():
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    data = request.get_json()
    thread_type = data.get("type", "course")
    course_id = data.get("course_id")
    participant_ids = data.get("participants", [])
    thread_name = data.get("thread_name", "")
    user_id = session["user_id"]
    
    try:
        # Create thread data
        thread_data = {
            "thread_type": thread_type,
            "created_by": user_id,
            "last_message_at": datetime.now(timezone.utc).isoformat()
        }
        
        if course_id:
            thread_data["course_id"] = course_id
            
            # Get course info for thread name
            course_response = (
                supabase
                .table("courses")
                .select("course_code, course_title")
                .eq("id", course_id)
                .single()
                .execute()
            )
            
            if course_response.data:
                if not thread_name:
                    thread_name = f"{course_response.data['course_code']} - {course_response.data['course_title']}"
        
        if thread_name:
            thread_data["thread_name"] = thread_name
        
        # Check if thread already exists (for direct messages)
        if thread_type == "direct" and len(participant_ids) == 1:
            existing_thread = (
                supabase
                .from_('chat_participants')
                .select('''
                    thread_id,
                    chat_threads!inner(thread_type)
                ''')
                .eq('user_id', user_id)
                .execute()
            )
            
            if existing_thread.data:
                for item in existing_thread.data:
                    thread = item.get('chat_threads')
                    if thread and thread['thread_type'] == 'direct':
                        # Check if this thread already has both users
                        thread_id = item['thread_id']
                        participants_response = (
                            supabase
                            .table("chat_participants")
                            .select("user_id")
                            .eq("thread_id", thread_id)
                            .execute()
                        )
                        
                        if participants_response.data:
                            participant_user_ids = [p['user_id'] for p in participants_response.data]
                            if participant_ids[0] in participant_user_ids:
                                return jsonify({
                                    "success": True,
                                    "thread_id": thread_id,
                                    "already_exists": True
                                })
        
        # Create thread
        thread_response = supabase.table("chat_threads").insert(thread_data).execute()
        
        if not thread_response.data:
            return jsonify({"error": "thread_creation_failed"}), 500
        
        thread_id = thread_response.data[0]["id"]
        
        # Add creator as participant
        participants_to_add = [{"thread_id": thread_id, "user_id": user_id}]
        
        # Add other participants
        for participant_id in participant_ids:
            if participant_id != user_id:
                participants_to_add.append({
                    "thread_id": thread_id,
                    "user_id": participant_id
                })
        
        # Add all participants
        supabase.table("chat_participants").insert(participants_to_add).execute()
        
        return jsonify({
            "success": True,
            "thread_id": thread_id,
            "already_exists": False
        })
        
    except Exception as e:
        print(f"Error creating chat thread: {e}")
        return jsonify({"error": "database_error"}), 500

@app.route("/api/chat/join-course/<course_id>", methods=["POST"])
def join_course_chat(course_id):
    if "user_id" not in session or session.get("role") != "student":
        return jsonify({"error": "unauthorized"}), 401
    
    student_id = session["user_id"]
    
    try:
        # Check if student is registered for this course
        registration_response = (
            supabase
            .table("course_registration")
            .select("*")
            .eq("course_id", course_id)
            .eq("student_id", student_id)
            .single()
            .execute()
        )
        
        if not registration_response.data:
            return jsonify({"error": "not_registered"}), 403
        
        # Check if course chat exists
        thread_response = (
            supabase
            .table("chat_threads")
            .select("id")
            .eq("course_id", course_id)
            .eq("thread_type", "course")
            .single()
            .execute()
        )
        
        thread_id = None
        
        if thread_response.data:
            # Join existing chat
            thread_id = thread_response.data["id"]
            
            # Check if already a participant
            participant_response = (
                supabase
                .table("chat_participants")
                .select("*")
                .eq("thread_id", thread_id)
                .eq("user_id", student_id)
                .execute()
            )
            
            if not participant_response.data:
                supabase.table("chat_participants").insert({
                    "thread_id": thread_id,
                    "user_id": student_id
                }).execute()
        
        else:
            # Create new course chat
            course_response = (
                supabase
                .table("courses")
                .select("course_code, course_title")
                .eq("id", course_id)
                .single()
                .execute()
            )
            
            if not course_response.data:
                return jsonify({"error": "course_not_found"}), 404
            
            course = course_response.data
            
            # Create thread
            thread_data = {
                "thread_type": "course",
                "course_id": course_id,
                "thread_name": f"{course['course_code']} - {course['course_title']}",
                "created_by": student_id,
                "last_message_at": datetime.now(timezone.utc).isoformat()
            }
            
            thread_response = supabase.table("chat_threads").insert(thread_data).execute()
            
            if not thread_response.data:
                return jsonify({"error": "chat_creation_failed"}), 500
            
            thread_id = thread_response.data[0]["id"]
            
            # Add student as participant
            supabase.table("chat_participants").insert({
                "thread_id": thread_id,
                "user_id": student_id
            }).execute()
            
            # Add lecturer as participant
            course_lecturer_response = (
                supabase
                .table("courses")
                .select("lecturer_id")
                .eq("id", course_id)
                .single()
                .execute()
            )
            
            if course_lecturer_response.data:
                lecturer_id = course_lecturer_response.data["lecturer_id"]
                if lecturer_id:
                    supabase.table("chat_participants").insert({
                        "thread_id": thread_id,
                        "user_id": lecturer_id
                    }).execute()
        
        return jsonify({
            "success": True,
            "thread_id": thread_id
        })
        
    except Exception as e:
        print(f"Error joining course chat: {e}")
        return jsonify({"error": "database_error"}), 500

@app.route("/api/chat/thread/<thread_id>/read", methods=["POST"])
def mark_thread_as_read_api(thread_id):
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    user_id = session["user_id"]
    
    try:
        # Mark all messages in thread as read
        supabase.table("chat_messages").update({
            "is_read": True,
            "read_at": datetime.now(timezone.utc).isoformat()
        }).eq("thread_id", thread_id).neq("sender_id", user_id).execute()
        
        return jsonify({"success": True})
        
    except Exception as e:
        print(f"Error marking thread as read: {e}")
        return jsonify({"error": "database_error"}), 500

@app.route("/api/chat/unread-count")
def get_unread_count_api():
    if "user_id" not in session:
        return jsonify({"count": 0})
    
    user_id = session["user_id"]
    
    try:
        # Count unread messages in threads user participates in
        unread_response = (
            supabase
            .rpc('get_unread_message_count', {
                'user_id': user_id
            })
            .execute()
        )
        
        if unread_response.data:
            count = unread_response.data[0].get('unread_count', 0)
        else:
            # Fallback query
            participant_threads_response = (
                supabase
                .table("chat_participants")
                .select("thread_id")
                .eq("user_id", user_id)
                .execute()
            )
            
            if not participant_threads_response.data:
                return jsonify({"count": 0})
            
            thread_ids = [pt["thread_id"] for pt in participant_threads_response.data]
            
            unread_messages_response = (
                supabase
                .table("chat_messages")
                .select("*", count="exact")
                .in_("thread_id", thread_ids)
                .eq("is_read", False)
                .neq("sender_id", user_id)
                .execute()
            )
            
            count = unread_messages_response.count if hasattr(unread_messages_response, 'count') else len(unread_messages_response.data)
        
        return jsonify({"count": count})
        
    except Exception as e:
        print(f"Error getting unread count: {e}")
        return jsonify({"count": 0})

# Add this RPC function too:
ADDITIONAL_RPC_FUNCTIONS = """
-- Get unread message count for user
CREATE OR REPLACE FUNCTION get_unread_message_count(user_id UUID)
RETURNS TABLE(
    unread_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT COUNT(*) as unread_count
    FROM chat_messages cm
    WHERE cm.thread_id IN (
        SELECT thread_id 
        FROM chat_participants 
        WHERE user_id = user_id
    )
    AND cm.is_read = FALSE
    AND cm.sender_id != user_id;
END;
$$ LANGUAGE plpgsql;
"""
# Add this after: app = Flask(__name__)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)