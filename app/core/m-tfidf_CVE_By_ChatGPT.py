from numpy.ma import count
import pandas as pd
from gensim.parsing.preprocessing import preprocess_documents

from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
import numpy as np, random
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import classification_report
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.metrics import average_precision_score, precision_recall_curve, auc
from sklearn.naive_bayes import GaussianNB
from sklearn import svm
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import roc_auc_score
from sklearn.metrics.pairwise import cosine_similarity
import warnings, random


# import openai
# import requests
# import json
# # Load your API key from an environment variable or secret management service
# openai.api_key = "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"

import openai

# openai.api_key = "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" #works 
openai.api_key = "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"


# List of questions
questions = [
    'how we can have cve number form chatGPT by using TTP information',
    'how we can have cve number form chatGPT by using TTP information'
]






def askQuestions():
    # Iterate through the questions
    for question in questions:
        # Create a completion request
        response = openai.Completion.create(
            engine='davinci',
            prompt=question,
            max_tokens=15
        )

        # Print the generated completion
        print(f"Question: {question}")
        print(f"Answer: {response.choices[0].text.strip()}")
        print("###############################################")


warnings.filterwarnings("ignore")

# implements TF-IDF
def splitTechniqueName(text):
    return text.split(':')[0]
def main():
    askQuestions()
    dfTactics = pd.read_excel('app/datasets/attack-data.xlsx', sheet_name=0)
    dfTechniques = pd.read_excel('app/datasets/attack-data.xlsx', sheet_name=2)
    dfProcedures = pd.read_excel('app/datasets/attack-data.xlsx', sheet_name=3)

    dfTacticsCut = dfTactics.loc[:, ['ID', 'name', 'description']]
    dfTacticsCut['type'] = 'tactics'
   
    dfTechniquesCut = dfTechniques.loc[:, ['ID', 'name', 'description']]
    dfTechniquesCut['type'] = 'techniques'

    dfTechniqueProcedureMerged = pd.merge(dfTechniques, dfProcedures, left_on='ID', right_on='target ID')

    dfProceduresCut = dfTechniqueProcedureMerged.loc[:, ['source ID', 'name', 'mapping description','target ID','description']]
    
    dfProceduresCut['procID'] = dfProceduresCut['source ID']
    dfProceduresCut['mapdescription'] = dfProceduresCut['mapping description']
    dfProceduresCut['techdescription'] = dfProceduresCut['description']
    dfProceduresCut['techId'] = dfProceduresCut['target ID']
    dfProceduresCut['techName'] = dfProceduresCut['name']
    dfProceduresCut['type'] = 'example'
    dfProceduresCut = dfProceduresCut.loc[:, ['procID', 'techName','techId','techdescription', 'mapdescription', 'type']]
    print(dfProceduresCut.head())
    # dataframe = pd.concat([dfTacticsCut, dfTechniquesCut, dfProceduresCut], ignore_index=True)
    
    # trainAndTestSet = dataframe.loc[dataframe['type'] == 'example']
    trainAndTestSet = dfProceduresCut
    trainAndTestSet['techName'] = trainAndTestSet['techName'].apply(splitTechniqueName) #Abuse Elevation Control Mechanism: Bypass User Account Control
    
    dataframe2 = pd.concat([trainAndTestSet], ignore_index=True)
    test = dataframe2.loc[:, ['procID', 'techName','techId','techdescription', 'mapdescription', 'type']]
    trainAndTestSet = test
    # for da in [1,2,3,4,5,6,7,10]:
    #     print(trainAndTestSet)
    #     print()
    result = pd.DataFrame()
    res = []
    org_description = trainAndTestSet.values
    print (trainAndTestSet.head())
    trainAndTestSet = trainAndTestSet.sample(n=10)
    for index, ttp in trainAndTestSet.iterrows():
        procID = ttp['procID'] 
        techName = ttp['techName'] 
        techId = ttp['techId'] 
        techdescription = ttp['techdescription'] 
        prodescription = ttp['mapdescription'] 
        string_query = 'technique ID:'+" "+techId+" ,technique Name:"+ techName+" , description:"+prodescription
        print (string_query)
        # res.append(string_query)
        question = "10 CVEs IDs examples for technique ID:"+techId
        # res.append(question)
        # Create a completion request
        
        try:
            response = openai.Completion.create(
                engine='davinci',
                prompt=question,
                max_tokens=1800
            )
            # result.
            print(f"Answer: {response.choices[0].text.strip()}")
            if 'CVE-' in response.choices[0].text.strip() :
                res.append(techId+"^"+response.choices[0].text.strip())
        except openai.error.InvalidRequestError as e:
            print (" ERRR")
    df = pd.DataFrame(res)
    df.to_excel('testChatGPTQuestions.xlsx', index=False)
   
  
    



def print_rows_matching_values(dataframe, procID, techName,cves, values_procedureId,values_techName,cves_values ):
    # matching_rows = dataframe[ dataframe['CVE-ID'].isin(cves_values) & dataframe['ID_x'].isin(values_procedureId) & dataframe[techName].isin(values_techName) ]  
    # matching_rows = matching_rows[matching_rows[techName].isin(values_techName)]
    # condition1 = dataframe['CVE-ID'].apply(lambda x: cves_values[x] == desired_value1)
    # matching_rows = dataframe[ condition1]
    matching_rows = dataframe[dataframe[procID].isin(values_procedureId)]
    # matching_rows = matching_rows[matching_rows[techName].isin(values_techName)]
    matching_rows = matching_rows[matching_rows[cves].isin(cves_values)]
    # matching_rows.to_excel('test100Tech.xlsx', index=False)
    new_rows = []
    for ind in range(len(cves)):
        for index, row in matching_rows.iterrows():
            if row[1] == cves_values[ind] and row[8] == values_procedureId[ind]:
                new_rows.append(row)
                print(row[1])
    df = pd.DataFrame(new_rows)
    df.to_excel('test100Tech.xlsx', index=False)
           

def printValuesMapping():
    values_tech = ['T1598.001']
    dfProcedures = pd.read_csv('dfAttackCVEMerged/dfAttackCVEbyCWEMerged3.csv')
    dfProcedures = dfProcedures[dfProcedures['target ID'].isin(values_tech)]
    # new_rows = []
    # for ind in range(len(values_tech)):
    #     for index, row in dfProcedures.iterrows():
    #         if values_tech[ind] in row[9] :
    #             new_rows.append(row)
    #             # print(row[1])
    # df = pd.DataFrame(new_rows)
    dfProcedures.to_excel('test4ChatGpt.xlsx', index=False)




if __name__ == "__main__":
    # main()
    printValuesMapping()
