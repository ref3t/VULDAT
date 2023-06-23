import pandas as pd
import re
from gensim.parsing.preprocessing import preprocess_documents
from sklearn.metrics.pairwise import cosine_similarity
from openpyxl import Workbook
import xlsxwriter
import numpy as np
import itertools

from sklearn.feature_extraction.text import TfidfVectorizer


def readAllDataCapecAttackCVECWE():
    dfProcedures = pd.read_csv('dfAttackCVEMerged/dfAttackCVEbyCWEMerged3.csv')
    return dfProcedures

def read_cve_file():
    dataCve = pd.read_excel('app/datasets/Vulnerability_Dataset.xlsx', sheet_name=0)
    
    dataCve = dataCve.loc[:, ['CVE-ID', 'DESCRIPTION']]
    return dataCve

def removeUrls (text):
    try:
        text = re.sub(r'(https|http)?:\/\/(\w|\.|\/|\?|\=|\&|\%)*\b', '', text, flags=re.MULTILINE)
        text = re.sub(r'\b\w*\d+\w*\b', '', text, flags=re.MULTILINE)
        return(text)
    except:
        return text

def removeURLsFromData(texts):
    return [removeUrls(text) for text in texts]

def dataPreprocessingCVE(cveData):
    cveDescriptions = cveData['DESCRIPTION'].values
    cveDescriptions = removeURLsFromData(cveDescriptions)
    processed_corpus = preprocess_documents(cveDescriptions)
    list_input = []
    for item in processed_corpus:
        text = ' '.join(item)
        list_input.append(text.strip())
    cveData['DESCRIPTION'] = list_input
    return cveData

def dataPreprocessingCAPECDescription(capecData):
    capecDes = capecData['Description'].values
    capecDes = removeURLsFromData(capecDes)
    processed_corpus = preprocess_documents(capecDes)
    list_input = []
    for item in processed_corpus:
        text = ' '.join(item)
        list_input.append(text.strip())
    capecData['Description'] = list_input
    return capecData

def tfidfCapecDescription(orgcve_description,rowData,cveData):
    input_string = rowData['Description'] 
    input_string = removeUrls(input_string)
    if pd.isnull(input_string):
        return 0, []
    processed_corpus_input = preprocess_documents([input_string])
    list_input = []
    for item in processed_corpus_input:
        text = ' '.join(item)
        list_input.append(text.strip())
    vectorizer = TfidfVectorizer(use_idf=True)
    vectors = vectorizer.fit_transform(cveData['DESCRIPTION'])
    input_tfidf = vectorizer.transform(list_input)
    similarity_scores = cosine_similarity(input_tfidf, vectors)
    closest_paragraph_indices = similarity_scores.argsort()[0][-1:]
    closest_paragraph_probabilities = [similarity_scores[0][index] for index in closest_paragraph_indices]
    for index2, probability in zip(closest_paragraph_indices, closest_paragraph_probabilities):
        return f"{float(probability)*100:.2f}", orgcve_description[index2]
        # print(f"{orgcve_description[index2][0]}###{orgcve_description[index2][1]}###{alldata}###{float(probability)*100:.2f}\n")
        # print (rowData['Description'])
        # print (orgcve_description[index2][1])
        # common_words = (set((rowData['Description']).split())).intersection(set((orgcve_description[index2][1]).split()))
        # print (common_words)



def combinedFeature(orgcve_description,columnArray,rowData,cveData):
    input_string = ''
    for item in columnArray:
        input_string = input_string+str(rowData[item])+" "
    # input_string = rowData['Skills Required'] 
    input_string = removeUrls(input_string)
    if pd.isnull(input_string):
        return 0, []
    processed_corpus_input = preprocess_documents([input_string])
    list_input = []
    for item in processed_corpus_input:
        text = ' '.join(item)
        list_input.append(text.strip())
    vectorizer = TfidfVectorizer(use_idf=True)
    vectors = vectorizer.fit_transform(cveData['DESCRIPTION'])
    input_tfidf = vectorizer.transform(list_input)
    similarity_scores = cosine_similarity(input_tfidf, vectors)
    closest_paragraph_indices = similarity_scores.argsort()[0][-10:]
    closest_paragraph_probabilities = [similarity_scores[0][index] for index in closest_paragraph_indices]
    optionsCVE = []
    for index2, probability in zip(closest_paragraph_indices, closest_paragraph_probabilities):
        optionsCVE.append([f"{float(probability)*100:.2f}", orgcve_description[index2]])
    return optionsCVE

def findMaxSimilarity(orgcve_description,alldata,cveData):
    CVEMergeALLcases = []

    #CWE
    CWEFeatures = ['CWE-NAME']
    tfidf10CWEDesSimilarity = combinedFeature(orgcve_description,CWEFeatures,alldata,cveData)
    tfidf10CWEDesSimilarity = [row + ['CWE:'+"CWE-NAME"] for row in tfidf10CWEDesSimilarity]
    # print (tfidf10CWEDesSimilarity[9])

    CVEMergeALLcases.extend(tfidf10CWEDesSimilarity)

    #CAPEC  with CWE 
    capecFeatures = ['Name','Description','Execution Flow','Prerequisites','Skills Required','Resources Required','Mitigations','Example Instances']
    combinations = list(itertools.product(CWEFeatures, capecFeatures))
    combinations = np.array(combinations)
    # print(combinations)
    maxCombin = 0
    pos = 0
    smiarityCombinCWECAPECMax = []
    for index,item in enumerate(combinations):
        smiarityCombinCWECAPEC = combinedFeature(orgcve_description,item,alldata,cveData)
        smiarityCombin = smiarityCombinCWECAPEC[9][0]
        if maxCombin < float (smiarityCombin):
            maxCombin = float(smiarityCombin)
            pos = index
            smiarityCombinCWECAPECMax = smiarityCombinCWECAPEC
    smiarityCombinCWECAPECMax = [row + ['CAPECCWE:'+str(combinations[pos])] for row in smiarityCombinCWECAPECMax]
    # print (smiarityCombinCWECAPECMax[9])

    CVEMergeALLcases.extend(smiarityCombinCWECAPECMax)
    # just CAPEC 
    capecFeatures = ['Name','Description','Execution Flow','Prerequisites','Skills Required','Resources Required','Mitigations','Example Instances']
    poscapec = 0
    maxSimalirityCAPEC = 0
    smiarityCombinCWECAPECOnly = []
    for index,item in enumerate(capecFeatures):
        smiarityCombinCWECAPEC = combinedFeature(orgcve_description,[item],alldata,cveData)
        smiarityCombin = smiarityCombinCWECAPEC[9][0]
        if maxSimalirityCAPEC < float (smiarityCombin):
            maxSimalirityCAPEC = float(smiarityCombin)
            poscapec = index
            smiarityCombinCWECAPECOnly = smiarityCombinCWECAPEC
    # print (smiarityCombinCWECAPECOnly[9])
    smiarityCombinCWECAPECOnly = [row + ['CAPEC:'+str(capecFeatures[poscapec])] for row in smiarityCombinCWECAPECOnly]

    CVEMergeALLcases.extend(smiarityCombinCWECAPECOnly)
    CVEMergeALLcases.sort(key=lambda x: x[0], reverse=True)
    # print(CVEMergeALLcases)
    return CVEMergeALLcases



def checkCAPECDesWithCVEsAndFindMaximum():   
    cveDataorg = read_cve_file()
    orgcve_description = cveDataorg.values
    cveData = dataPreprocessingCVE(cveDataorg)
    capecData = readAllDataCapecAttackCVECWE()
    capecData  = capecData.sample(n=50)
    result_df = pd.DataFrame(columns=['Max_TFIDF_Similarity', 'CVE_ID','CVE_Description','MaxSimilarity_By','index','CVE-ID','CVSS-V3','CVSS-V2','SEVERITY','DESCRIPTION','CWE-ID','CWE-NAME','ID_x','target ID','name','descriptionTechniques','description','type','ID_y','Name','Description','Likelihood Of Attack','Typical Severity','Execution Flow','Prerequisites','Skills Required','Resources Required','Indicators','Mitigations','Example Instances','Related Weaknesses','Taxonomy Mappings','ATTACK_techniques_name'])
    capecData = dataPreprocessingCAPECDescription(capecData)
    contrun = 0
    for index, alldata in capecData.iterrows():
        print (contrun +1)
        contrun = contrun + 1
        CVEMergeALLcases = findMaxSimilarity(orgcve_description,alldata,cveData)
        CVEMergeALLcases = [item for item in CVEMergeALLcases if float(item[0]) > smilarityThreshold]
        # print (alldata)
        for ind, data in enumerate(CVEMergeALLcases):
            result_df = pd.concat([result_df, pd.DataFrame({'Max_TFIDF_Similarity': [data[0]], 'CVE_ID':[data[1][0]],'CVE_Description':[data[1][1]],'MaxSimilarity_By':[data[2]],'CVE-ID':alldata['CVE-ID'],'CVSS-V3':alldata['CVSS-V3'],'CVSS-V2':alldata['CVSS-V2'],'SEVERITY':alldata['SEVERITY'],'DESCRIPTION':alldata['DESCRIPTION'],'CWE-ID':alldata['CWE-ID'],'CWE-NAME':alldata['CWE-NAME'],'ID_x':alldata['ID_x'],'target ID':alldata['target ID'],'name':alldata['name'],'descriptionTechniques':alldata['descriptionTechniques'],'description':alldata['description'],'type':alldata['type'],'ID_y':alldata['ID_y'],'Name':alldata['Name'],'Description':alldata['Description'],'Likelihood Of Attack':alldata['Likelihood Of Attack'],'Typical Severity':alldata['Typical Severity'],'Execution Flow':alldata['Execution Flow'],'Prerequisites':alldata['Prerequisites'],'Skills Required':alldata['Skills Required'],'Resources Required':alldata['Resources Required'],'Indicators':alldata['Indicators'],'Mitigations':alldata['Mitigations'],'Example Instances':alldata['Example Instances'],'Related Weaknesses':alldata['Related Weaknesses'],'Taxonomy Mappings':alldata['Taxonomy Mappings'],'ATTACK_techniques_name':alldata['ATTACK_techniques_name']})], ignore_index=True)
    result_df.to_excel('BestResultsCVECWECAPEC.xlsx', index=False)



smilarityThreshold = 50
checkCAPECDesWithCVEsAndFindMaximum()