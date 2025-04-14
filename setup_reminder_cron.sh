#!/bin/bash

# Setup script for scheduling the daily questionnaire reminder at 12 PM (GMT+7)
echo "Setting up cron job for daily questionnaire reminders at 12 PM (GMT+7)..."

# Get the absolute path to the project directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_PATH=$(which python)
MANAGE_PY="$PROJECT_DIR/manage.py"

# Create a temporary cron file
TEMP_CRON=$(mktemp)
crontab -l > "$TEMP_CRON" 2>/dev/null || echo "# Questionnaire Reminders Cron" > "$TEMP_CRON"

# Add the cron job (checks if it exists first)
if ! grep -q "send_questionnaire_reminders" "$TEMP_CRON"; then
    echo "0 12 * * * cd $PROJECT_DIR && $PYTHON_PATH $MANAGE_PY send_questionnaire_reminders" >> "$TEMP_CRON"
    echo "Cron job added"
else
    echo "Cron job already exists"
fi

# Install the cron job
crontab "$TEMP_CRON"
rm "$TEMP_CRON"

echo "Reminder setup complete! Questionnaire reminders will be sent daily at 12 PM (GMT+7)."
echo "You can test it by running: python manage.py send_questionnaire_reminders" 