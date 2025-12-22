#!/bin/bash
python -c "from app import app, initialize_database; initialize_database()"
gunicorn app:app --bind 0.0.0.0:$PORT