FROM python:3.12-slim

WORKDIR /app
COPY api-server-test.py /app/api-server-test.py

EXPOSE 8089
CMD ["python", "api-server-test.py"]
