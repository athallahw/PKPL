from django.db import connection
from django.shortcuts import render

def playing_with_neon_view(request):
    # Fetch data from the 'playing_with_neon' table
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT name, value
            FROM playing_with_neon
            """
        )
        rows = cursor.fetchall()

    # Konversi hasil query ke format yang lebih mudah digunakan di template
    data = [{'name': row[0], 'value': row[1]} for row in rows]
    
    # Print the data in the terminal (opsional)
    for row in rows:
        print(f"Name: {row[0]}, Value: {row[1]}")
    
    # Render template dengan data
    return render(request, 'landingpage.html', {'data': data})


