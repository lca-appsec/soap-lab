FROM python:3.12-slim

WORKDIR /app
COPY server.py /app/server.py
COPY vulnerable_server.py /app/vulnerable_server.py
COPY run_both.py /app/run_both.py

EXPOSE 8088 8089
CMD ["python", "run_both.py"]
