from twilio.rest import Client


account_sid = 'Enter_your_account_sid'
auth_token = 'Enter_your_auth_token'
client = Client(account_sid, auth_token)


def send_sms(content):
  message = client.messages.create(
    from_='Enter_your_temp_number',
    to='Enter_your_phone_number',
    body=content,
  )

  print(message.sid)