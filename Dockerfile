FROM python:3
ADD monitor.py /
ADD traffic.csv .
RUN pip install user-agents
CMD [ "python", "./monitor.py", "-f", "traffic.csv"]