# Questionnaire Email Reminders

## Overview
The system automatically sends reminder emails to users who haven't filled out their daily health questionnaire at 12 PM (GMT+7) each day.

## Configuration

### Email Settings
Email reminders are sent using the following configuration in `.env`:
```
EMAIL_HOST_USER=asthazhorif@gmail.com
EMAIL_HOST_PASSWORD=njqy lnvd wygx cdcl
```

### Schedule
Reminders are scheduled to be sent daily at 12 PM (GMT+7).

## Setup Instructions

1. Make sure the Django project is properly configured with email settings
2. Run the setup script to configure the cron job:
   ```
   ./setup_reminder_cron.sh
   ```

## Manual Testing

To manually test the reminder system, run:
```
python manage.py send_questionnaire_reminders
```

This will send reminder emails to all users who haven't submitted their questionnaire for the current day.

## Implementation Details

The reminder system consists of:
- A Django management command (`send_questionnaire_reminders.py`)
- A cron job that executes the command daily at 12 PM
- Email configuration in the project settings

The reminder checks which users haven't submitted a questionnaire for the current day and sends them a reminder email. 