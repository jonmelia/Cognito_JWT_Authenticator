from flask import Flask, request
import webbrowser

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <html><body>
    <a href="https://your-domain.auth.eu-west-1.amazoncognito.com/login?response_type=token&client_id=your_client_id&redirect_uri=http://localhost:5000/callback">
        Login with Cognito
    </a>
    </body></html>
    '''

@app.route('/callback')
def callback():
    return '''
    <html><body>
    <script>
        const params = new URLSearchParams(window.location.hash.substring(1));
        const token = params.get('id_token');
        document.write("<h3>Your ID Token:</h3><textarea rows='10' cols='80'>" + token + "</textarea>");
    </script>
    </body></html>
    '''

if __name__ == '__main__':
    webbrowser.open("http://localhost:5000")
    app.run(port=5000)