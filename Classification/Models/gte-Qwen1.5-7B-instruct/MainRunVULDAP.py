import pandas as pd
import re
from gensim.parsing.preprocessing import preprocess_documents
from sklearn.metrics.pairwise import cosine_similarity
from openpyxl import Workbook
import xlsxwriter
import numpy as np
import random
import itertools
from transformers import AutoTokenizer, AutoModel
from sklearn.metrics.pairwise import cosine_similarity
import torch
from sklearn.feature_extraction.text import TfidfVectorizer
# from app.core.vulDataClass  import VulData
import sys
# Add the directory containing vulDataClass.py to the Python module search path
sys.path.append('c:/Users/RAmneh/OneDrive - Scientific Network South Tyrol/Desktop/P.hD Stuff/SRC/VULDAP/vulDataClass/')

from vulDataClass  import VulData
from sentence_transformers import SentenceTransformer, util
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer, WordNetLemmatizer
from sklearn import preprocessing
nltk.download('stopwords')
nltk.download('punkt')
nltk.download('wordnet')


def trueNegativeSUM(vul_data_array,cve_ids_A_not_attack,Threeshold):
    count = 0
    if len(cve_ids_A_not_attack) > 0:
        for vuldat in vul_data_array:
            if float(vuldat.CVE_Smiliraty) < Threeshold:
                if vuldat.CVE_ID in cve_ids_A_not_attack:
                    count = count +1
    # #print("*******************************************total CVEs from VULDAT less 50 And Exist In A***************************************************")
    # #print(count)

    count2 = 0
    if len(cve_ids_A_not_attack) > 0:
        for item in cve_ids_A_not_attack:
            flag = 0 
            for vuldat in vul_data_array:
                if item == vuldat.CVE_ID:
                    flag = 1 
                    break
            if flag == 0:
                count2 = count2 +1
    # #print("*******************************************not In VULDAT But In A ***************************************************")
    # #print(count2)

    #print("**********TTTTTTTTNNNNNNNNNN ***************************************************")
    #print((count2+count))
    return count,count2


def readProcedures():

    file_pathPositive = 'NewMapping/FinalResultSeperate/Procedures/ALLProcedures.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['ProceduresID', 'ProcedureDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('ProceduresID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('ProceduresID').to_dict(orient='index')
    # Return the dictionary if needed
    return data_dictP


def readProceduresPositive():

    file_pathPositive = 'NewMapping/FinalResultSeperate/Procedures/ProceduresPositives.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['ProceduresID', 'ProcedureDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('ProceduresID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('ProceduresID').to_dict(orient='index')
    # Return the dictionary if needed
    return data_dictP

def readCAPEC():
    file_pathPositive = 'NewMapping/FinalResultSeperate/CAPEC/ALLAttackPatterns.xlsx'
    # Read the Excel fileCAPECID	CAPECName	CAPECDescription

    data = pd.read_excel(file_pathPositive, header=0, names=['CAPECID', 'CAPECName', 'CAPECDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('CAPECID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('CAPECID').to_dict(orient='index')
    # Return the dictionary if needed
    return data_dictP

def readTactics():
    file_pathPositive = 'NewMapping/FinalResultSeperate/Tactic/AllTactics.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TacticId', 'TacticName', 'TacticDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TacticId').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TacticId').to_dict(orient='index')
    # Return the dictionary if needed
    return data_dictP

def readsubTechniques():
    file_pathPositive = 'NewMapping/FinalResultSeperate/SubTechniques/AllSubTechniques.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TechnqiueID').to_dict(orient='index')

    count = 0
    # data_dictP.update(data_dictNegative)
     # Print the resulting dictionary using a for loop
    # for key, value in data_dictP.items():
    #     #print(f"{count}ID: {key}\tTechnique: {value['TechnqiueName']}\tDescription: {value['TechnqiueDescription']}")
    #     count = count +1

    # Return the dictionary if needed
    return data_dictP

def readAllTech():
    file_pathPositive = './data/AllTechniques.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TechnqiueID').to_dict(orient='index')

    # for key, value in data_dictP.items():
    #     #print(f"{count}ID: {key}\tTechnique: {value['TechnqiueName']}\tDescription: {value['TechnqiueDescription']}")
    #     count = count +1

    # Return the dictionary if needed
    return data_dictP


def readTechWithNegative():
    file_pathPositive = './data/FinalTechniquesPositive.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TechnqiueID').to_dict(orient='index')

    # file_pathNegative = 'NewMapping/FinalResultSeperate/Techniqes/FinalTechniquesNegative.xlsx'
    # # Read the Excel file
    # data = pd.read_excel(file_pathNegative, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    
    # # Group by 'ID' and aggregate other columns into lists
    # grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()

    # # Create a dictionary from the grouped data
    # data_dictNegative = grouped_data.set_index('TechnqiueID').to_dict(orient='index')
    # Your existing code to create data_dictNegative
    file_pathNegative = './data/FinalTechniquesNegative.xlsx'
    data = pd.read_excel(file_pathNegative, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()
    data_dictNegative = grouped_data.set_index('TechnqiueID').to_dict(orient='index')

    # Convert dictionary items to a list
    dict_items = list(data_dictNegative.items())

    # Randomly select 59 items
    random_items = random.sample(dict_items, 59)

    # Convert the selected items back to a dictionary
    data_dictNegative = dict(random_items)


    count = 0
    # data_dictP.update(data_dictNegative)
     # Print the resulting dictionary using a for loop
    # for key, value in data_dictP.items():
    #     #print(f"{count}ID: {key}\tTechnique: {value['TechnqiueName']}\tDescription: {value['TechnqiueDescription']}")
    #     count = count +1

    # Return the dictionary if needed
    return data_dictP




def readTechData():
    # Read the Excel file
    file_path = 'ALLTechniquesData.xlsx'
    data = pd.read_excel(file_path, header=0, names=['ATTACK-target ID', 'ATTACK-techniques-name'])

    # Convert the data to a dictionary
    techniques_dict = dict(zip(data['ATTACK-target ID'], data['ATTACK-techniques-name']))

    # Print the resulting dictionary using a for loop
    for key, value in techniques_dict.items():
        print(f"ID: {key}\tTechnique: {value}")
    return techniques_dict
    
# readTechData()
def readAllDataCapecAttackCVECWE():
    dfProcedures = pd.read_csv('dfAttackCVEMerged/dfAttackCVEbyCWEMerged3.csv')
    return dfProcedures

def read_cve_file():
    dataCve = pd.read_excel('app/datasets/Vulnerability_Dataset.xlsx', sheet_name=0)
    
    dataCve = dataCve.loc[:, ['CVE-ID', 'DESCRIPTION']]
    return dataCve



import re


def remove_citations_and_urls(text):
    
    # Regular expression pattern to match citations
    citation_pattern = r'\(Citation:.*?\)'

    # Regular expression pattern to match URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

    # Find all occurrences of citations in the text
    citations = re.findall(citation_pattern, text)

    # Remove each citation from the text
    for citation in citations:
        text = text.replace(citation, '')

    # Find all occurrences of URLs in the text
    urls = re.findall(url_pattern, text)

    # Remove each URL from the text
    for url in urls:
        text = text.replace(url, '')
    regex = "^<code>.*</code>$"
    text = re.sub(regex, "",text, flags=re.MULTILINE) 
    text = " ".join(text.split()) # remove extra spaces
    text = re.sub("[^A-Za-z0-9]", " ", text) # replace anything that is not alphanumeric with empty string
    # text = text.replace("\t", " ")
    return text

# checkCVEUsingBert()
def removeUrls (text):
    # print (text)
    text = re.sub(r'(https|http)?:\/\/(\w|\.|\/|\?|\=|\&|\%)*\b', '', text, flags=re.MULTILINE)
    text = re.sub(r'(?i)NOTE:.*', '', text)
    # text = re.sub(r'\b\w*\d+\w*\b|\b\w*\.\w*\b', '', text)
    # text = re.sub(r'\.\w+\b', '', text)
    # text = re.sub(r'[^\w\s]', '', text)
    # text = re.sub(r'\b\w*\d+\w*\b', '', text)
    # text = re.sub(r'\s+', ' ', text)
    # text = re.sub(r'\d+', '', text)
    # text = re.sub(r'[,."()]', '', text)
    text = re.sub(r'\b\d+(\.\d+)*\b', '', text) #remove digits 
    # print (text)
    return(text)


def removeCitation(text):
    position = text.find('(Citation:')
    if position > 0:
        return text[:position]
    else:
        return text

def removeURLandCitationBulk(texts):
    return [remove_citations_and_urls(text) for text in texts]
# red = removeURLandCitationBulk(['Untrusted search path vulnerability in  PGP Desktop 9.9.0 Build 397, 9.10.x, 10.0.0 Build 2732,and probably other versions allows local users,and possibly remote attackers,to execute arbitrary code and conduct DLL hijacking attacks via a Trojan horse tsp.dll or tvttsp.dll that is located in the same folder as a .p12,.pem,.pgp,.prk,.prvkr,.pubkr,.rnd or .skr file.'])

def dataPreprocessingStopWords(texts):
    return [preprocess_text_stop_words(text) for text in texts]

def dataPreprocessingStemming(texts):
    return [preprocess_text_stemming(text) for text in texts]

def dataPreprocessingLemmatization(texts):
    return [preprocess_text_lemmatization(text) for text in texts]

def preprocess_text_stop_words(text):
    # Tokenization
    tokens = word_tokenize(text)
    stop_words = set(stopwords.words('english'))

    # Stop words removal
    tokens = [token for token in tokens if token not in stop_words]
        
    return tokens
#Stemming is the process of finding the root of words
def preprocess_text_stemming(text):
    # Tokenization
    tokens = word_tokenize(text)
    stemmer = PorterStemmer()
    # Stemming
    stemmed_tokens = [stemmer.stem(token) for token in tokens]
    
    return stemmed_tokens
#Lemmatization is the process of finding the form of the related word in the dictionary.
def preprocess_text_lemmatization(text):
    # Tokenization
    tokens = word_tokenize(text)
    
    lemmatizer = WordNetLemmatizer()
    # Lemmatization
    lemmatized_tokens = [lemmatizer.lemmatize(token) for token in tokens]
    
    return lemmatized_tokens
# df = pd.DataFrame(columns=['Threshold','TechID','TP', 'FP', 'FN', 'TP0,1', 'FP0,1','FN0,1','TPNormalize','FPNormalize','FNNormalize'])

df = pd.DataFrame(columns=['Threshold','TechID','TP', 'FP', 'FN', 'TN','AttackTP','AttackTN','AttackFP','AttackFN','CountMapping'])
dfRes = pd.DataFrame(columns=['TechID','Negative','Positive', 'Retrieved by VULDAT', 'Not retrieved by VULDAT','Predicted Positives (>50)','Predicted Negatives (<50)','True Positives (>50)','False Positives (>50)','True Negatives ( <50)','True Negatives (not retrieved)','False Negatives (<50)','False Negatives (not retrieved)','AttackTP','AttackTN','AttackFP','AttackFN'])

def falseNegativeSUMAlltech2222(vul_data_array,CVEsAttack,techniquesID,arrayPositive ,arrayNegative,CvesNotAttack, Threeshold):
    global df
    global dfRes
    global procedure_dict
    
    arrayPositive2 = arrayPositive
    arrayPositive = len(arrayPositive)
    arrayNegative2 = arrayNegative
    arrayNegative = len(arrayNegative)
    countMapping = 0
    MappingCVEsVuldatForAttack = []
    MappingCVEsVuldatNotForAttack = []
    if len(CVEsAttack) > 0:
        for vuldat in vul_data_array:
            # if float(vuldat.CVE_Smiliraty) < smilarityThreshold:
            if vuldat.CVE_ID in CVEsAttack:
                MappingCVEsVuldatForAttack.append(vuldat.CVE_ID)
                countMapping = countMapping +1
    # #print("*******************************************total CVEs from VULDAT less 50 And Exist In C***************************************************")
    # #print(count)
    MappingCVEsVuldatForAttack = list(set(MappingCVEsVuldatForAttack))
    countMapping = len(MappingCVEsVuldatForAttack)

    
    count = 0
    CVEsVuldatForAttack = []
    CVEsVuldatNotForAttack = []
    if len(CVEsAttack) > 0:
        for vuldat in vul_data_array:
            if float(vuldat.CVE_Smiliraty) < Threeshold:
                if vuldat.CVE_ID in CVEsAttack:
                    CVEsVuldatForAttack.append(vuldat.CVE_ID)
                    count = count +1
    # #print("*******************************************total CVEs from VULDAT less 50 And Exist In C***************************************************")
    # #print(count)
    CVEsVuldatForAttack = list(set(CVEsVuldatForAttack))
    count = len(CVEsVuldatForAttack)

    count2 = 0
    for item in CVEsAttack:
        flag = 0 
        for vuldat in vul_data_array:
            if item == vuldat.CVE_ID:
                flag = 1 
                break
        if flag == 0:
            CVEsVuldatNotForAttack.append(item)
            count2 = count2 +1
    CVEsVuldatNotForAttack = list(set(CVEsVuldatNotForAttack))
    count2 = len(CVEsVuldatNotForAttack)
    # #print("*******************************************not In VULDAT But In C ***************************************************")
    # #print(count2)

    # #print("**********FFFFFFFFFFFFFFFNNNNNNNNNN ***************************************************")
    # #print("FN:" + str(count2+count))
    # #print("***************************************************")
    # PredictedNegatives2 = PredictedNegatives(vul_data_array,Threeshold)
    # PredictedPositives2 = PredictedPositives(vul_data_array,Threeshold)
    trueNeativeResless, trueNeativeResNotRetrived  = ResTrueNegatives(vul_data_array, CvesNotAttack,Threeshold)
    AttackTP = 0 
    AttackTN =0 
    AttackFP=0 
    AttackFN =0
    if ((arrayNegative+arrayPositive)) > 0  and countMapping > 0:
        AttackTP = 1 
    elif ((arrayNegative+arrayPositive)) == 0  and countMapping == 0:
        AttackTN = 1 
    elif ((arrayNegative+arrayPositive)) > 0  and countMapping == 0:
        AttackFP = 1 
    elif ((arrayNegative+arrayPositive)) == 0  and countMapping > 0:
        AttackFN = 1
    # if ((arrayPositive)) > 0  and countMapping > 0:
    #     AttackTP = 1 
    # elif (arrayPositive) == 0  and countMapping == 0:
    #     AttackTN = 1 
    # elif (arrayPositive) > 0  and countMapping == 0:
    #     AttackFP = 1 
    # elif (arrayPositive) == 0  and countMapping > 0:
    #     AttackFN = 1 
    df = pd.concat([df, pd.DataFrame({'Threshold':[Threeshold*100],'TechID':[techniquesID],'TP': [arrayPositive], 'FP': [arrayNegative], 'FN': [(count2+count)], 'TN': [(trueNeativeResless+trueNeativeResNotRetrived)], 'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)]})], ignore_index=True)
    # dfRes = pd.concat([dfRes, pd.DataFrame({'TechID':[capecID], 'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)],'Lpositive':[arrayPositive2],'LNegatives':[arrayNegative2],"Mapping":[MappingCVEsVuldatForAttack]})], ignore_index=True)
    dfRes = pd.concat([dfRes, pd.DataFrame({'TechID':[techniquesID], 'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)],'Lpositive':[arrayPositive2],'LNegatives':[arrayNegative2],"Mapping":[MappingCVEsVuldatForAttack]})], ignore_index=True)

procedure_dict = {}
def ResTrueNegatives(vul_data_array, CvesNotAttack,Threeshold):
    return trueNegativeSUM(vul_data_array,CvesNotAttack,Threeshold)
def PredictedNegatives(vul_data_array,Threeshold):
    count = 0 
    for vuldat in vul_data_array:
        if float(vuldat.CVE_Smiliraty) < Threeshold:
            count = count + 1
    return count
def PredictedPositives(vul_data_array, Threeshold):
    count = 0 
    for vuldat in vul_data_array:
        if float(vuldat.CVE_Smiliraty) >= Threeshold:
            count = count + 1
    return count

def reportConvisionMatrix(vul_data_array,MCVEsAttack,key,arrayTruePositiveAttack,falsePositiveAttack,Threeshold):
    global df
    global dfRes
    global procedure_dict
    MCVEsAttack = list(set(MCVEsAttack))
    FalseNegative = list(filter(lambda x: x not in arrayTruePositiveAttack, MCVEsAttack))
    AttackTP = 0 
    AttackFP=0 
    AttackFN =0
    if len(arrayTruePositiveAttack)> 0:
        AttackTP = 1 
    if len(falsePositiveAttack)> 0:
        AttackFP = 1 
    if len(FalseNegative)> 0:
        AttackFN = 1
    ListModel = [len(arrayTruePositiveAttack),len(falsePositiveAttack),len(FalseNegative)]
    normalized_array = np.array(ListModel)

    normalized_arr = preprocessing.normalize([normalized_array])
    df = pd.concat([df, pd.DataFrame({'Threshold':[Threeshold*100],'TechID':[key],'TP': [len(arrayTruePositiveAttack)], 'FP': [len(falsePositiveAttack)], 'FN': [len(FalseNegative)], 'TP0,1': [(AttackTP)], 'FP0,1': [(AttackFP)], 'FN0,1': [(AttackFN)], 'TPNormalize': [(normalized_arr[0][0])], 'FPNormalize': [(normalized_arr[0][1])], 'FNNormalize': [(normalized_arr[0][2])]})], ignore_index=True)


def checkCVEUsingAllTech():
    global df
    global dfRes
    # readTechDataMITRE()
    model = SentenceTransformer("Alibaba-NLP/gte-Qwen1.5-7B-instruct", trust_remote_code=True)
    allLinksFile = "./data/VULDATDataSetWithoutProcedures.xlsx"
    # allLinksFile = "NewMapping/FinalResultSeperate/Techniqes/FinalTechwitthCVEs.xlsx"
    print ("Im here1")
    dataCve = pd.read_excel(allLinksFile, sheet_name=0)
    # dataCve = dataCve.loc[:, ['DESCRIPTION']]
    descriptions = dataCve['CVEDescription'].values
    orgDescriptions = dataCve
    dataCve2= dataCve
    print ("Im here2")

    # descriptions = removeURLandCitationBulk(descriptions)
    # descriptions = dataPreprocessingStopWords(descriptions)
    # descriptions = [' '.join(item) for item in descriptions]    
    # print ("Im here3")
    # descriptions = dataPreprocessingStemming(descriptions)
    # descriptions = [' '.join(item) for item in descriptions]
    # descriptions = dataPreprocessingLemmatization(descriptions)
    # descriptions = [' '.join(item) for item in descriptions]
    dataCve['CVEDescription'] = descriptions 
    print ("Im here3")

    
    descriptions = dataCve['CVEDescription'].values.tolist()
    techniquesName = dataCve['TechnqiueName'].values.tolist()
    CWEName = dataCve['CAPECName'].values.tolist()
    CapecDes = dataCve['CAPECDescription'].values.tolist()
    descriptions = descriptions[:len(descriptions)]
    techniquesName = techniquesName[:len(techniquesName)]
    CWEName = CWEName[:len(CWEName)]
    # joined_list = [ descriptions[i] for i in range(min(len(descriptions), len(techniquesName)))]

    joined_list = [ techniquesName[i]+ " " + descriptions[i] for i in range(min(len(descriptions), len(techniquesName)))]
    print ("Im here4")

    sentences = joined_list
    # sentences = ["A man is eating a piece of bread.", "perltidy through 20160302, as used by perlcritic, check-all-the-things, and other software, relies on the current working directory for certain output files and does not have a  symlink-attack protection mechanism, which allows local users to overwrite arbitrary files by  creating a symlink, as demonstrated by creating a perltidy.ERR symlink that the victim cannot delete.", 'A DLL Hijacking vulnerability in Eatons 9000x Programming and Configuration Software v 2.0.38 and prior allows an attacker to execute arbitrary code by replacing the required DLLs with malicious DLLs when the software try to load vci11un6.DLL and cinpl.DLL.','A   vulnerability in Eatons 9000x Programming and Configuration Software v 2.0.38 and prior allows an attacker to execute arbitrary code by replacing the required  with malicious when the software try to load vci11un6. and cinpl']
    embeddings = model.encode(sentences)

    techniquesName = dataCve['TechnqiueName'].values.tolist()
    # techniquesID = dataCve['TechnqiueID'].values.tolist()
    # techniquesDes = dataCve['TechnqiueDescription'].values.tolist()
    # capecName = dataCve['CAPECName'].values.tolist()
    # CapecDes = dataCve['CAPECDescription'].values.tolist()
    # CweDes = dataCve['CWE-Description'].values.tolist()
    # CweName = dataCve['CWE-Name'].values.tolist()
    # ProcDesription = dataCve['ATTACK-procedure-description'].values.tolist()
    # ProcIDs = dataCve['ATTACK-Procedure-ID'].values.tolist()
    print ("Im here5")
    # tech_dict = readTechData()
    # informationData = ["Tactic", "Technique","subTechniques","Procedures","CAPEC"]
    informationData = ["Technique"]

    for infoData in informationData:
        if infoData == "Tactic":
            tech_dict = readTactics()
        elif infoData == "Technique":
            tech_dict = readTechWithNegative()
        elif infoData == "subTechniques":
            tech_dict = readsubTechniques()
        elif infoData == "Procedures":
            tech_dict = readProcedures()
        elif infoData == "prcedirePositive":
            tech_dict = readProceduresPositive()
        elif infoData == "CAPEC":
            tech_dict = readCAPEC()
    
        # for Threeshold in [0.05,0.10,0.15,0.20,0.25,0.30,0.35,0.40,0.45,0.50,0.55,0.60,0.65,0.70,0.75,0.80,0.85,0.90,0.95]:
        for Threeshold in [0.60]:
            df = df.iloc[0:0]
            dfRes = df.iloc[0:0]
            countT = 0
            print(str(Threeshold) + " Threshold")
            for key, value in tech_dict.items():
            #     for key, value in attach_dict.items():
            # #print(f"{count}TechnqiueID: {key}\tTechnique: {value['TechnqiueName']}\tDescription: {value['TechnqiueDescription']}")
                print(f"ID: {key} ttttt {countT} ")
                countT = countT+1
                # if countT >4:
                #     break
                attack_texts = [f"{value['TechnqiueName']} {value['TechnqiueDescription']}"]
                # if infoData == "Tactic":
                #     # attack_texts = removeURLandCitationBulk([f"{value['TacticName']} {value['TacticDescription']}"])
                #     attack_texts = removeURLandCitationBulk([f"{value['TacticDescription']}"])
                # elif infoData == "Procedures" or infoData == "prcedirePositive":
                #     attack_texts = removeURLandCitationBulk([f"{value['ProcedureDescription']}"])
                # elif infoData == "CAPEC":
                #     # attack_texts = removeURLandCitationBulk([f"{value['CAPECName']} {value['CAPECDescription']}"])
                #     attack_texts = removeURLandCitationBulk([f"{value['CAPECDescription']}"])
                # else:
                #     attack_texts = removeURLandCitationBulk([f"{value['TechnqiueName']} {value['TechnqiueDescription']}"])
                # attack_texts = dataPreprocessingStemming(attack_texts)
                # attack_texts = [' '.join(item) for item in attack_texts]        
                vul_data_array =[]
            
                external_embedding = model.encode(attack_texts)

                # Compute cosine similarities
                similarities = util.pytorch_cos_sim(external_embedding, embeddings)


                # Calculate cosine similarities
                similarities = cosine_similarity(external_embedding.reshape(1, -1), embeddings)[0]

                # Get indices of top 10 closest sentences
                top_10_indices = np.argsort(similarities)[-181000:][::-1]

                # Print top 10 closest sentences
                # orgDescriptions  = dataCve
                finalRes =[]
                array = []
                
                for index in top_10_indices:
                    
                    if orgDescriptions.loc[index] is not None:
                        if not dataCve.loc[index]['CVEID'] in array:
                            array.append(dataCve.loc[index]['CVEID'])
                            # #print(joined_list[index])
                            vul_data = VulData()
                            vul_data.CVE_ID = orgDescriptions.loc[index]['CVEID']
                            vul_data.CVE_Des = orgDescriptions.loc[index]['CVEDescription']
                            vul_data.CWE_ID = orgDescriptions.loc[index]['CWE-ID']
                            vul_data.CWE_NAME = orgDescriptions.loc[index]['CWE-Name']
                            # vul_data.CWE_Des = orgDescriptions.loc[index]['CWE-Description']
                            # vul_data.CWE_extended_des = orgDescriptions.loc[index]['CWE-Extended Description']
                            # vul_data.CWE_Detection_Methods = orgDescriptions.loc[index]['CWE-Detection Methods']
                            # vul_data.CWE_Potential_Mitigations = orgDescriptions.loc[index]['CWE-Potential Mitigations']
                            # vul_data.ATTACK_Procedure_ID = orgDescriptions.loc[index]['ATTACK-Procedure-ID']
                            # vul_data.ATTACK_target_ID = orgDescriptions.loc[index]['ATTACK-target ID']
                            # vul_data.ATTACK_techniques_name = orgDescriptions.loc[index]['ATTACK-techniques-name']
                            # vul_data.ATTACK_techniques_descriptionTechniques = orgDescriptions.loc[index]['ATTACK-techniques-descriptionTechniques']
                            # vul_data.ATTACK_procedure_description = orgDescriptions.loc[index]['ATTACK-procedure-description']
                            # vul_data.CAPEC_Name = orgDescriptions.loc[index]['CAPEC-Name']
                            # vul_data.CAPEC_Description = orgDescriptions.loc[index]['CAPEC-Description']
                            # vul_data.CAPEC_Typical_Severity = orgDescriptions.loc[index]['CAPEC-Typical Severity']
                            # vul_data.CAPEC_Execution_Flow = orgDescriptions.loc[index]['CAPEC-Execution Flow']
                            # vul_data.CAPEC_Prerequisites = orgDescriptions.loc[index]['CAPEC-Prerequisites']
                            # vul_data.CAPEC_Skills_Required = orgDescriptions.loc[index]['CAPEC-Skills Required']
                            # vul_data.CAPEC_Resources_Required = orgDescriptions.loc[index]['CAPEC-Resources Required']

                            # vul_data.CAPEC_Mitigations = orgDescriptions.loc[index]['CAPEC-Mitigations']
                            vul_data.CVE_Smiliraty  = f"{similarities[index]:.4f}"
                            # if vul_data._CVE_Smiliraty >= smilarityThreshold:
                            # if float(vul_data.CVE_Smiliraty) > 0.32:
                            finalRes.append(vul_data.CVE_ID + "#" +vul_data.CVE_Des+"#"+vul_data.CVE_Smiliraty )
                            vul_data_array.append(vul_data)
                # print ("refat")
                # print (contrun)
                # print (len(array))
                # print (len(vul_data_array))
                
                
                # contrun = contrun + 1
                # dataCve = pd.read_excel(allLinksFile, sheet_name=0)
                dataCve =dataCve2
                if infoData == "Tactic":
                    trainAndTestSet = dataCve[dataCve['TacticID'] == key]
                elif infoData == "Procedures" or infoData == "prcedirePositive":
                    trainAndTestSet = dataCve[dataCve['ProceduresID'] == key]
                elif infoData == "CAPEC":
                    trainAndTestSet = dataCve[dataCve['CAPECID'] == key]
                else:
                    if "." in key:
                        key = key.split(".")[0]
                    trainAndTestSet = dataCve[dataCve['TechnqiueID'].str.startswith(key)]

                
                # trainAndTestSet = dataCve.loc[dataCve['TechnqiueID'] == key]
                # trainAndTestSet = dataCve[dataCve['TechnqiueID'].str.startswith(key)]
                # trainAndTestSet = dataCve[dataCve['ATTACK-target ID'].str.startswith(techid.split(".")[0])]
                trainAndTestSetCVEs = trainAndTestSet['CVEID']
                trainAndTestSetCVEs2 = trainAndTestSetCVEs.tolist()
                trainAndTestSetCVEs = list(set(trainAndTestSetCVEs2))
                #### not attack
                if infoData == "Tactic":
                    CvesNotAttack = dataCve[dataCve['TacticID'] != key]
                elif infoData == "Procedures" or infoData == "prcedirePositive":
                    CvesNotAttack = dataCve[dataCve['ProceduresID'] != key]
                elif infoData == "CAPEC":
                    CvesNotAttack = dataCve[dataCve['CAPECID'] != key]
                else:
                    if "." in key:
                        key = key.split(".")[0]
                    CvesNotAttack = dataCve[~dataCve['TechnqiueID'].str.startswith(key)]
                # CvesNotAttack = dataCve[dataCve['TechnqiueID'] != key]
                # CvesNotAttack = dataCve[~dataCve['TechnqiueID'].str.startswith(key)]
                CvesNotAttack = CvesNotAttack['CVEID']
                CvesNotAttack = CvesNotAttack.tolist()
                CvesNotAttack = list(set(CvesNotAttack))
                CvesNotAttack = list(filter(lambda x: x not in trainAndTestSetCVEs, CvesNotAttack))

                arrayPositive = []
                arrayNegative = []

                for item in vul_data_array:
                    if float(item.CVE_Smiliraty) > Threeshold:
                        flag = 1
                        for cve in trainAndTestSetCVEs:
                            if item.CVE_ID == cve:
                                arrayPositive.append(item.CVE_ID)
                                flag = 0
                                break
                        if flag == 1:
                            arrayNegative.append(item.CVE_ID)
                arrayPositive = list(set(arrayPositive))
                arrayNegative = list(set(arrayNegative))
                # #print("******************************************Tppp****************************************************")
                print(f"TP:{str(len(arrayPositive))}    FP: {str(len(arrayNegative))}   {str(key)}")
                # #print(arrayPositive)
                # #print("*******************************************FPnnn***************************************************")
                # #print(len(arrayNegative))
                # #print(arrayNegative)
                # falseNegativeTitleTech(vul_data_array)
                # falseNegativeTitleTechproc(vul_data_array)
                # falseNegativeTitleTechAllproc(vul_data_array)
                # falseNegativeTitleTechAllTech(vul_data_array)
                # techid = techIDs[count]
                # reportConvisionMatrix(vul_data_array,trainAndTestSetCVEs,key,arrayPositive,arrayNegative,Threeshold)

                falseNegativeSUMAlltech2222(vul_data_array,trainAndTestSetCVEs,key,arrayPositive , arrayNegative,CvesNotAttack, Threeshold)
                # count = count +1
        df.to_excel(f"Final{infoData}_withOutPreProcessing2Full.xlsx", index=False)
        dfRes.to_excel(f"Final{infoData}_withOutPreProcessing22Full.xlsx", index=False)

#########################################################################Hijack Execution Flow: DLL Search Order Hijacking Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program. [1][2] Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.There are many ways an adversary can hijack DLL loads. Adversaries may plant trojan dynamic-link library files (DLLs) in a directory that will be searched before the location of a legitimate library that will be requested by a program, causing Windows to load their malicious library when it is called for by the victim program. Adversaries may also perform DLL preloading, also called binary planting attacks, [3] by placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL. Often this location is the current working directory of the program.[4] Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL. [5]Adversaries may also directly modify the search order via DLL redirection, which after being enabled (in the Registry and creation of a redirection file) may cause a program to load a different DLL.[6][7][8]If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program. Programs that fall victim to path hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace. has used search order hijacking to force TeamViewer to load a malicious DLL is a cybercriminal group that has been active since at least 2015 and is primarily interested in users of remote banking systems in Russia and neighboring countries. The group uses a Trojan by the same name 
checkCVEUsingAllTech()
