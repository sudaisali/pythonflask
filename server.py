import json
import requests
from authlib.integrations.flask_client import OAuth
import os
from flask import Flask, abort, redirect, render_template, session, url_for , request
from uuid import uuid4 
from flask import send_file

app = Flask(__name__)

appConf = {
    "OAUTH2_CLIENT_ID": "331225223576-f12jtnme58qt4vjg8boufceu6edbi2ma.apps.googleusercontent.com",
    "OAUTH2_CLIENT_SECRET": "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",
    "OAUTH2_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": "3727007b-3020-48c9-ba45-b11024abb345",
    "FLASK_PORT": 5000
}

app.secret_key = appConf.get("FLASK_SECRET")

oauth = OAuth(app)

oauth.register(
    "myApp",
    client_id=appConf.get("OAUTH2_CLIENT_ID"),
    client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email https://www.googleapis.com/auth/user.birthday.read https://www.googleapis.com/auth/user.gender.read",
    },
    server_metadata_url=f'{appConf.get("OAUTH2_META_URL")}',
)


@app.route("/")
def home():
    if "user_identifier" in session:
        return render_template("dashboard.html", session=session.get("user"),
                           pretty=json.dumps(session.get("user"), indent=4))
    else:
        return render_template("home.html", session=session.get("user"),
                           pretty=json.dumps(session.get("user"), indent=4))

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", session=session.get("user"),
                           pretty=json.dumps(session.get("user"), indent=4))

@app.route("/downloadexpAnalysis/<user_identifier>/<filename>", methods=['GET'])
def downloadexpAnalysis(user_identifier, filename):
    try:
    
        file_path = os.path.abspath(os.path.join('temp', user_identifier, 'exploratory_analysis', filename))

        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            return "File not found", 404  
    except Exception as e:
        app.logger.error(f"Error during file download: {str(e)}")
        return "Internal Server Error", 500  

@app.route("/downloadthmAnalysis/<user_identifier>/<filename>", methods=['GET'])
def downloadthmAnalysis(user_identifier, filename):
    try:
        
        file_path = os.path.abspath(os.path.join('temp', user_identifier, 'theme_based_analysis', filename))

        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            return "File not found", 404  
    except Exception as e:
        
        app.logger.error(f"Error during file download: {str(e)}")
        return "Internal Server Error", 500  

@app.route("/exploratory_analysis", methods=['GET', 'POST'])
def exploratoryAnalysis():
    if request.method == 'POST':
        user_identifier = session.get('user_identifier')

        if not user_identifier:
            abort(401)

        exploratory_folder = os.path.join('temp', user_identifier, 'exploratory_analysis')

        if not os.path.exists(exploratory_folder):
            os.makedirs(exploratory_folder)

        file1 = request.files['file1']
        file2 = request.files['file2']

        if file1 and file2:
            file1.save(os.path.join(exploratory_folder, file1.filename))
            file2.save(os.path.join(exploratory_folder, file2.filename))
            download_link = url_for('downloadexpAnalysis', user_identifier=user_identifier, filename=file1.filename)
        
            return render_template("exp_analysis_Download.html", download_link=download_link , session=session.get("user"),
                           pretty=json.dumps(session.get("user"), indent=4))

    return render_template("expolatoryAnalysis.html", session=session.get("user"), pretty=json.dumps(session.get("user"), indent=4))

@app.route("/theme_based_analysis", methods=['GET', 'POST'])
def themeAnalysis():
    if request.method == 'POST':
        user_identifier = session.get('user_identifier')

        if not user_identifier:
            abort(401)

        theme_folder = os.path.join('temp', user_identifier, 'theme_based_analysis')
        if not os.path.exists(theme_folder):
            os.makedirs(theme_folder)

        file1 = request.files['file1']
        file2 = request.files['file2']

        if file1 and file2:
            file1.save(os.path.join(theme_folder, file1.filename))
            file2.save(os.path.join(theme_folder, file2.filename))
            download_link = url_for('downloadthmAnalysis', user_identifier=user_identifier, filename=file1.filename)
            
            return render_template("theme_analysis_Download.html", download_link=download_link ,session=session.get("user"),
                           pretty=json.dumps(session.get("user"), indent=4))

    return render_template("themeAnalysis.html", session=session.get("user"), pretty=json.dumps(session.get("user"), indent=4))

@app.route("/signin-google")
def googleCallback():
    token = oauth.myApp.authorize_access_token()
    personDataUrl = "https://people.googleapis.com/v1/people/me?personFields=genders,birthdays"
    personData = requests.get(personDataUrl, headers={
        "Authorization": f"Bearer {token['access_token']}"
    }).json()
    token["personData"] = personData
    session["user"] = token
    email = session["user"]["userinfo"]["email"]
    sub = session["user"]["userinfo"]["nonce"]
    print(email)
    print("sudais")
    
    if email:
        unique_id = str(uuid4())  
        user_identifier = f"{email}"
        session["user_identifier"] = user_identifier
        print(f"Email: {email}")
        print(f"User Identifier: {user_identifier}")
    return redirect(url_for("home"))


@app.route("/google-login")
def googleLogin():
    if "user" in session:
        abort(404)
    return oauth.myApp.authorize_redirect(redirect_uri=url_for("googleCallback", _external=True))


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=appConf.get(
        "FLASK_PORT"), debug=True)