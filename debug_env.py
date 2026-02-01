# debug_env.py
import os
from dotenv import load_dotenv

# Force load from the specific path to be sure
env_path = os.path.join(os.path.dirname(__file__), '.env')
loaded = load_dotenv(env_path)

print(f"Loading .env from: {env_path}")
print(f"Did .env load? {loaded}")
print(f"SUPABASE_URL: {os.environ.get('SUPABASE_URL')}")