from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def home():
    return "Server Running"

@app.route('/run')
def run():
    cmd = request.args.get('cmd')  # get the input from phone/browser

    # write the input to cloud_in.txt
    with open("cloud_in.txt", "a") as f:
        f.write(cmd + "\n")

    return f"<pre>Command received: {cmd}</pre>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
