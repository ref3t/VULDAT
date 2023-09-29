from flask import Flask, render_template, request
import core.CVECAPEC_TFIDF as VulCheck
from flask_paginate import Pagination, get_page_args
import threading
import time

vulDetails = []

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])

def home():
    
    if request.method == 'POST':
        if 'findDes' in request.form:
            description = request.form['description']
            vulData = VulCheck.checkCVEUsingBert2(description)
            global vulDetails
            vulDetails = vulData
            print(vulData[0].CVE_ID)

            return render_template('index.html', res=vulData , show_table = True, description = description)
        elif 'formfindAllInfo' in request.form:
            description = request.form.get('description')
            hidden_data_1 = request.form.get('hidden-data-1')
            vulDetails2 = VulCheck.getCveData(vulDetails,hidden_data_1)
            # resCwes = cve.getAllCweRelated(hidden_data_1)
            return render_template('index.html', res=vulDetails2, show_table = False, cveID=hidden_data_1, description = description)
        # elif 'formfindAllCWE' in request.form:
        #     hidden_data_1 = request.form.get('hidden-data-1')
        #     resCwes = cve.getAllCweRelated(hidden_data_1)
        #     return render_template('index.html', res=resCwes, show_table = False, cweID=hidden_data_1)
        elif 'Back' in request.form:
            description = request.form.get('description')
            return render_template('index.html', res=vulDetails , show_table = True, description = description)
    return render_template('index.html', res =[] , show_table = False)

if __name__ == '__main__':
    app.run(debug=True)

