FROM python:3.13-alpine
WORKDIR /app
RUN addgroup -S app && adduser -S app -G app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
USER app
EXPOSE 8000
CMD ["python", "app.py"]
