FROM python:2

WORKDIR /app

RUN pip install --no-cache-dir awscli requests
RUN apt-get update && apt-get install -y git \
  && git clone https://github.com/gchamon/sandcastle.git /app \
  && apt-get remove -y git

ENTRYPOINT ["python", "sandcastle.py"]

