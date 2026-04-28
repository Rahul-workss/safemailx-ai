import pandas as pd
import os

OUTPUT_PATH = "../data/clean_emails.csv"

# Synthetic legitimate emails that look highly structured and contain links (just like phishing normally does),
# but represent actual benign corporate/automated traffic.
synthetic_legit = [
    """Medium Daily Digest: 5 Stories Selected for You. 
    1. How I Built a Neural Network in 10 minutes. Read more at http://bit.ly/med-nn
    2. The truth about Python scaling. https://link.medium.com/2Axy
    You are receiving this email because you subscribed to the Medium Digest newsletter.
    Click here to unsubscribe: https://medium.com/unsubscribe
    """,
    """Quora Digest: English Programming.
    What is the most difficult programming language?
    100 Answers - Read on Quora: https://qrs.ly/1234
    Unsubscribe from these emails anytime.
    """,
    """Google Scholar Alert: "machine learning phishing detection"
    New results for your alert:
    1. "A novel hybrid framework for email security." by Doe et al.
    Read it now: https://scholar.google.com/alert?id=xxx
    Cancel alert here.
    """,
    """LinkedIn: You appeared in 15 searches this week!
    See who's looking at your profile. Your network is growing.
    Upgrade to Premium to see all viewers: http://lnkd.in/premium
    Manage your email settings on the LinkedIn website.
    """,
    """Azure Cloud Security Alert: Maintenance window scheduled.
    Important notice regarding your account: We are updating our database clusters.
    This requires zero immediate action from you.
    Read the documentation: https://aka.ms/azure-updates
    """,
    """Verify your email address for GitHub.
    Please verify your account to unlock full features.
    Click here to verify: https://github.com/verify?token=123
    If you did not request this, please ignore this message.
    """,
    """Your Amazon.com order #111-232-13233 has shipped!
    Track your package: https://amzn.to/track123
    Important notice regarding your order: It will arrive tomorrow by 9 PM.
    Thank you for shopping with us!
    """,
    """Uber Receipts: Your Monday morning trip with John.
    Total: $14.53. Thank you for riding with Uber.
    Download your full receipt PDF here: http://t.uber.com/receipt
    """,
    """Spotify: Your 2026 Wrapped is finally here!
    You listened to 45,000 minutes of Synthwave.
    Click here to share your stats on Instagram: http://spoti.fi/wrapped
    """,
    """Slack: Unread messages in #development channel.
    Attention required: You have 4 unread messages and 2 mentions.
    Log in immediately to respond: https://slack.com/login
    """,
    """Dropbox: File sharing notification.
    Alice shared 'Q4_Financials.pdf' with you using Dropbox.
    View the file securely here: http://dbx.com/view/123
    """,
    """Zoom: Your meeting recording is ready.
    The recording for 'Q2 All Hands' is available. 
    Passcode: 123456. Watch it here: https://zoom.us/rec/play/xxx
    """,
    """Atlassian Jira: Ticket assigned to you.
    [DEV-999] Fix authentication bug on mobile app.
    Status: IN PROGRESS. View ticket: http://jira.company.com/browse/DEV-999
    """,
    """Action required: Review your Netflix subscription details.
    Your billing cycle renews on the 15th. We noticed a recent login from a new device.
    If this was you, no action is required.
    Manage devices: https://netflix.com/account
    """,
    """We've updated our Privacy Policy.
    Important notice regarding your account: Please review these changes.
    Read the new policy carefully at http://bit.ly/privacy-update
    """,
    """Salesforce: Daily metrics digest.
    You closed 3 deals yesterday. Keep up the good work!
    Log in to see your dashboard: https://login.salesforce.com
    """,
    """Eventbrite: Tickets for 'Tech Summit 2026'.
    Your order is confirmed. Present this barcode at the entrance.
    Download the Eventbrite app for faster check-in: https://evt.br/app
    """,
    """Welcome to the New York Times Newsletter.
    Breaking news: Markets hit an all-time high today.
    Read the full analysis here: http://nyti.ms/markets
    """,
    """Stripe: Payment successful for Invoice #INV-123.
    You received a payment of $1,200.00 from ACME Corp.
    View receipt details: https://dashboard.stripe.com/receipts
    """,
    """Zoom Info: A contact downloaded your whitepaper.
    Bob Smith (bob@example.com) accessed your PDF regarding email security.
    Follow up immediately: http://zminfo.ly/lead/123
    """
]
# Create 10 more to heavily enforce the pattern (total 30)
more_legit = [
    "AWS Billing Alert: You have exceeded 80% of your Free Tier limit for Amazon S3. Please review your usage on the console immediately: https://aws.amazon.com/console",
    "Patreon: New post from your favorite creator! Click here to read the early access content: http://patreon.com/posts/123",
    "Instacart: Your groceries are on the way. Track your driver in real-time: https://inst.cr/track",
    "Airbnb: Your reservation in Tokyo is confirmed! Check your itinerary and message the host here: http://abnb.me/tokyo",
    "PayPal: You paid $45.00 to Steam Games. If you didn't authorize this transaction, visit the Resolution Center: https://paypal.com/resolution",
    "Discord: You missed 15 messages in the #general channel. See what your friends are talking about: http://discord.gg/chat",
    "Duolingo: You lost your 14-day streak! Practice now for just 5 minutes to get it back: https://duolingo.com/lesson",
    "YouTube: Someone replied to your comment on 'How to build an AI'. Read their reply here: http://youtu.be/reply123",
    "Expedia: Final reminder before your trip! Check-in starts in 24 hours. Access your boarding pass: https://expd.co/flight",
    "Apple: Your receipt from Apple. Apple Music Subscription - $10.99. If you did not make this purchase, manage your subscriptions here: https://apple.com/account"
]
synthetic_legit.extend(more_legit)

print(f"Adding {len(synthetic_legit)} highly complex legitimate emails to the dataset...")

df = pd.read_csv(OUTPUT_PATH)
new_df = pd.DataFrame({"text": synthetic_legit, "label": ["legitimate"] * len(synthetic_legit)})

# Append without duplicates
combined_df = pd.concat([df, new_df]).drop_duplicates(subset=['text'])

combined_df.to_csv(OUTPUT_PATH, index=False)
print("Saved clean_emails.csv with augmented automated traffic data.")
