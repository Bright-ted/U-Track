import schedule
import time
from datetime import datetime, timedelta, timezone
from app import app, supabase, get_all_expired_sessions

def cleanup_expired_sessions():
    """Background task to clean up expired sessions"""
    with app.app_context():
        print(f"[{datetime.now()}] Running session cleanup...")
        expired = get_all_expired_sessions()
        if expired:
            print(f"  Closed {len(expired)} expired sessions: {expired}")
        else:
            print("  No expired sessions found")

def main():
    """Run scheduled cleanup tasks"""
    # Run cleanup every 5 minutes
    schedule.every(5).minutes.do(cleanup_expired_sessions)
    
    # Also run immediately on startup
    cleanup_expired_sessions()
    
    print("Session cleanup scheduler started. Running every 5 minutes.")
    
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute

if __name__ == "__main__":
    main()