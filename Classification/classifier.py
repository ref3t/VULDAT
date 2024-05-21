from sentence_transformers import SentenceTransformer, util
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import numpy as np

# Load a pre-trained model
model = SentenceTransformer('all-MiniLM-L6-v2')

# Example data
X = ["This is a positive sentence.", "This is a negative sentence."]
y = [[1, 0, 1], [0, 1, 0]]  # Multi-hot encoded labels

# Split data
X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, random_state=42)
X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)

# Convert sentences to embeddings
X_train_embeddings = model.encode(X_train, convert_to_tensor=True)
X_val_embeddings = model.encode(X_val, convert_to_tensor=True)
X_test_embeddings = model.encode(X_test, convert_to_tensor=True)

# Define the nearest neighbors classification function for multi-label
def classify_using_nearest_neighbors(train_embeddings, train_labels, test_embeddings, threshold=0.5):
    predictions = []
    for test_emb in test_embeddings:
        # Compute cosine similarities
        similarities = util.pytorch_cos_sim(test_emb, train_embeddings)[0]
        # Aggregate label predictions from the k nearest neighbors
        k = 5  # Number of nearest neighbors to consider
        nearest_indices = np.argsort(similarities)[-k:]
        nearest_labels = np.array([train_labels[i] for i in nearest_indices])
        # Average the labels of the nearest neighbors
        avg_labels = np.mean(nearest_labels, axis=0)
        # Convert average labels to binary predictions based on a threshold
        predicted_labels = (avg_labels >= threshold).astype(int)
        predictions.append(predicted_labels)
    return predictions


# Custom function to calculate metrics for multi-label classification
def evaluate_multilabel(y_true, y_pred):
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, average='weighted')
    recall = recall_score(y_true, y_pred, average='weighted')
    f1 = f1_score(y_true, y_pred, average='weighted')
    roc_auc = roc_auc_score(y_true, y_pred, average='weighted', multi_class='ovr')
    return accuracy, precision, recall, f1, roc_auc

# Validate the classifier
y_val_pred = classify_using_nearest_neighbors(X_train_embeddings, y_train, X_val_embeddings)
val_accuracy, val_precision, val_recall, val_f1, val_roc_auc = evaluate_multilabel(y_val, y_val_pred)
print(f"Validation Accuracy: {val_accuracy}")
print(f"Validation Precision: {val_precision}")
print(f"Validation Recall: {val_recall}")
print(f"Validation F1 Score: {val_f1}")
print(f"Validation ROC-AUC: {val_roc_auc}")


# Final evaluation on test set
y_test_pred = classify_using_nearest_neighbors(X_train_embeddings, y_train, X_test_embeddings)
test_accuracy, test_precision, test_recall, test_f1, test_roc_auc = evaluate_multilabel(y_test, y_test_pred)

print(f"Test Accuracy: {test_accuracy}")
print(f"Test Precision: {test_precision}")
print(f"Test Recall: {test_recall}")
print(f"Test F1 Score: {test_f1}")
print(f"Test ROC-AUC: {test_roc_auc}")
