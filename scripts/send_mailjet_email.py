import os
from mailjet_rest import Client

# 1. Initialize the Mailjet client
# It is best practice to use environment variables for security.
# Replace with your actual keys if you are hardcoding them: Client(auth=('API_KEY', 'API_SECRET'), version='v3.1')
api_key = os.environ.get('MJ_APIKEY_PUBLIC', 'your_public_api_key_here')
api_secret = os.environ.get('MJ_APIKEY_PRIVATE', 'your_private_api_key_here')

mailjet = Client(auth=(api_key, api_secret), version='v3.1')

# 2. Construct the email payload
data = {
    'Messages': [
        {
            'From': {
                'Email': 'you@yourdomain.com',  # Must be a verified sender domain/email in Mailjet
                'Name': 'Your Name or Company'
            },
            'To': [
                {
                    'Email': 'recipient@example.com',
                    'Name': 'Recipient Name'
                }
            ],
            'Subject': 'Testing Mailjet API v3.1 via Python',
            'TextPart': 'Hello from Mailjet! This is the plain text version of the email.',
            'HTMLPart': '<h3>Hello from Mailjet!</h3><p>This is the <strong>HTML</strong> version of the email.</p>',
            'CustomID': 'TransactionalTestEmail'  # Optional tracking identifier
        }
    ]
}

# 3. Send the request
try:
    response = mailjet.send.create(data=data)

    # 4. Handle the response status
    if response.status_code == 200:
        print("Success! Email sent successfully.")
        print(response.json())
    else:
        print(f"Failed to send email. Status code: {response.status_code}")
        print(response.json())

except Exception as e:
    print(f"An error occurred while connecting to Mailjet: {str(e)}")
