<!DOCTYPE html>
   <html lang="en">
   <head>
       <meta charset="UTF-8">
       <meta name="viewport" content="width=device-width, initial-scale=1.0">
       <title>Edit PDF</title>
       <link rel="stylesheet" href="{{ url_for('static', filename='styles.css') }}">
   </head>
   <body>
       <h1>Edit PDF</h1>
       <div id="pdf-pages">
           {% for image in images %}
               <img src="{{ url_for('static', filename=image) }}" alt="PDF Page">
           {% endfor %}
       </div>
       <form action="/recompile_pdf" method="POST">
           <button type="submit">Recompile PDF</button>
       </form>
   </body>
   </html>