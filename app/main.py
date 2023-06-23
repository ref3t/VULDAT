from flask import Flask, render_template, request
import core.cve_cwe as cve
from flask_paginate import Pagination, get_page_args
import threading
import time
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])

def home():
    res = ''
    if request.method == 'POST':
        if 'findDes' in request.form:
            description = request.form['description']
            res, similarity = cve.getDescription(description)
            cweID = res[2]
            return render_template('index.html', res=res , show_table = True, cweID = res[2])
        elif 'formfindAllCWE' in request.form:
            hidden_data_1 = request.form.get('hidden-data-1')
            resCwes = cve.getAllCweRelated(hidden_data_1)
            return render_template('index.html', res=resCwes, show_table = False, cweID=hidden_data_1)
    return render_template('index.html', res =[] , show_table = False)

if __name__ == '__main__':
    app.run(debug=True)
