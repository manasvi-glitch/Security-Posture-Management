"""
Launcher so you can start the server with VS Code's "Run Python File"
button or `python run.py` from the backend folder.

(Running app/main.py directly fails with "No module named 'app'" because
Python only adds that file's own folder to the import path.)
"""
import os
import uvicorn

if __name__ == "__main__":
    # Make sure relative paths (the SQLite file, the static folder) resolve
    # next to this file no matter where VS Code launches it from.
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    uvicorn.run("app.main:app", host="127.0.0.1", port=8420, reload=True)
