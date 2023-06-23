from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split

# Step 1: Preprocessing
def preprocess_text(text):
    # Implement your preprocessing steps here
    # Example: lowercase conversion, removal of punctuation, etc.
    processed_text = text.lower()
    return processed_text

# Step 2: Load and preprocess the corpus
corpus = ["This is the first document",
          "This document is the second document",
          "And this is the third one",
          "Is this the first document"]
labels = ["Label 1", "Label 2", "Label 3", "Label 4"]

preprocessed_corpus = [preprocess_text(doc) for doc in corpus]

# Step 3: Feature extraction using TF-IDF
vectorizer = TfidfVectorizer()
tfidf_matrix = vectorizer.fit_transform(preprocessed_corpus)

# Step 4: Split the data into training and validation sets
X_train, X_val, y_train, y_val = train_test_split(tfidf_matrix, labels, test_size=0.2, random_state=42)

# Step 5: Train a machine learning model
model = SVC(kernel='linear')
model.fit(X_train, y_train)

# Step 6: Classify a new document
new_text = "And this is the third one"
preprocessed_new_text = preprocess_text(new_text)
new_text_vector = vectorizer.transform([preprocessed_new_text])

# # Step 7: Calculate cosine similarity between the new document and the corpus
# cosine_similarities = cosine_similarity(new_text_vector, tfidf_matrix).flatten()

# # Step 8: Find the closest match using cosine similarity
# threshold = 0.5
# matched_indices = [i for i, score in enumerate(cosine_similarities) if score > threshold]

# if len(matched_indices) > 0:
#     closest_match_index = matched_indices[0]
#     closest_match_label = labels[closest_match_index]
# else:
#     closest_match_index = None
#     closest_match_label = "No match found"

# Step 9: Classify the new document using the machine learning model
new_text_prediction = model.predict(new_text_vector)

# Print the results
# print("Closest Match Index:", closest_match_index)
# print("Closest Match Label:", closest_match_label)
print("New Text Prediction:", new_text_prediction)
