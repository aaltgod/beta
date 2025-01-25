FROM python:3

WORKDIR /checker

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "pytest", "-s", "-v" ]
