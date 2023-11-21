# VULDAT
VULDAT is a novel approach proposed in the current repository. VULDAT stands for Automated Vulnerability Detection From Cyberattack Text. It is a method that uses natural language processing and machine learning techniques to recommend software vulnerabilities from textual descriptions of cyberattacks. VULDAT can help cybersecurity experts to identify and prioritize vulnerabilities based on real threats and to develop more effective mitigation strategies. VULDAT uses information from the MITRE repositories, such as ATT&CK, CAPEC, CWE, and CVE, to create a dataset of attacks and vulnerabilities. VULDAT also uses a sentence transformer model to compute semantic similarity between attack texts and vulnerability descriptions and to produce a ranked list of relevant CVEs. VULDAT can also recommend new links between attacks and vulnerabilities that are not yet established in the repositories.

# Data Description
The VULDAT approach uses four datasets from the MITRE repositories, which are:

- ATT&CK: A repository of information about adversary tactics and techniques gathered from real-world observations. It serves as a basis for the development of specific threat methodologies and approaches within the domain of cybersecurity.
- CAPEC: A catalogue of common attack patterns, tactics, and techniques adversaries use to exploit vulnerabilities. It provides a common language for describing and analyzing cyberattacks.
- CWE: A community-developed collection of common software weaknesses, coding errors, and security flaws. It provides a standard framework for identifying and classifying software vulnerabilities and their root causes.
- CVE: A list of publicly known cybersecurity vulnerabilities and exposures, each with a unique identification number and a brief description. It provides a reference point for vulnerability information and facilitates information sharing among security communities.



# HOW To Use The Scripts
Pre-Requirements
  - Python3
  - sklearn
  - gensim
  - numpy
  - nltk
    
How to use
- First use  https://github.com/ref3t/VULDAT/blob/master/app/main.py to run the server
- Insert any Attack Text 


