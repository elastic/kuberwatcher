FROM python:3.10

RUN mkdir /usr/src/app

WORKDIR /usr/src/app

COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

COPY . .

CMD ["python", "kuberwatcher.py"]
