FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY key_automaton.py .
COPY templates/ templates/

EXPOSE 8000

CMD ["python", "key_automaton.py"]
