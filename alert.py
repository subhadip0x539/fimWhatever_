import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from odd_jobs import compare_db_kin
import os
from AES_CBC import zip
from datetime import datetime


def notify(users, data, alertlog, analytics, baseline, baseline_bak, alert):
	alertlog(**data).save()
	analytics.objects().update(**{'alerts': len(alertlog.objects())})
	if alert:
		send_alert(data, users)

def send_alert(data, users):
	msg = MIMEMultipart('alternative')
	msg['Subject'] = "Alert!"
	msg['From'] = [doc['email'] for doc in users.objects(role='root')][0]
	msg['To'] = ",".join([doc['email'] for doc in users.objects(status__ne=0)])

	f = open("alert.txt", "r")
	temp = f.read()
	html2 = temp.format(file_id=data['file_id'], crnt_time=datetime.now().strftime("%d-%b-%Y %H:%M:%S").upper()+", IN")

	part1 = MIMEText(html2, 'html')
	part2 = MIMEText(html2, 'html')
	msg.attach(part1)
	with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
		smtp.starttls()
		smtp.login(os.environ.get('MAIL_USER'), os.environ.get('MAIL_PASS'))
		smtp.sendmail(msg['From'], msg['To'].split(","), msg.as_string())


