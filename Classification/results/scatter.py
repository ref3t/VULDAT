
# import pandas as pd
# import matplotlib.pyplot as plt

# # Sample data
# data = {
#     "TechID": ["T1003", "T1005", "T1007", "T1012", "T1014", "T1016", "T1018", "T1021", "T1027", "T1033", "T1039", "T1046", "T1049", "T1057", "T1080", "T1082", "T1083", "T1087", "T1092", "T1110", "T1111", "T1113", "T1115", "T1120", "T1123", "T1124", "T1125", "T1135", "T1176", "T1185", "T1211", "T1213", "T1217", "T1499", "T1528", "T1530", "T1534", "T1539", "T1554", "T1555", "T1566", "T1590", "T1598", "T1615", "T1620"],
#     "Intersection": [2, 26, 12, 6, 2, 10, 9, 5, 92, 14, 1, 7, 12, 7, 3, 8, 33, 12, 3, 14, 30, 7, 16, 13, 14, 11, 7, 12, 6, 30, 4, 2, 11, 39, 36, 2, 13, 124, 18, 2, 19, 11, 20, 10, 10],
#     "Union": [40, 88, 34, 23, 13, 26, 35, 32, 130, 35, 32, 41, 35, 27, 61, 37, 90, 29, 11, 53, 40, 20, 23, 20, 18, 22, 20, 40, 33, 110, 35, 6, 28, 57, 51, 5, 27, 151, 26, 17, 28, 32, 26, 20, 23],
#     "Jaccard": [0.05, 0.30, 0.35, 0.26, 0.15, 0.38, 0.26, 0.16, 0.71, 0.40, 0.03, 0.17, 0.34, 0.26, 0.05, 0.22, 0.37, 0.41, 0.27, 0.26, 0.75, 0.35, 0.70, 0.65, 0.78, 0.50, 0.35, 0.30, 0.18, 0.27, 0.11, 0.33, 0.39, 0.68, 0.71, 0.40, 0.48, 0.82, 0.69, 0.12, 0.68, 0.34, 0.77, 0.50, 0.43]
# }


# # Create DataFrame
# df = pd.DataFrame(data)

# # Set 'TechID' as index
# df.set_index('TechID', inplace=True)

# # Rename columns
# df = df.rename(columns={"Intersection": r'$\mathcal{L} \cap \mathcal{M}$', "Union": r'$\mathcal{L} \cup \mathcal{M}$'})

# # Plot
# fig, ax1 = plt.subplots(figsize=(12, 6))

# # Clustered column chart for Intersection and Union
# df[[r'$\mathcal{L} \cap \mathcal{M}$', r'$\mathcal{L} \cup \mathcal{M}$']].plot.bar(ax=ax1, color=['blue', 'orange'], alpha=0.7)

# ax1.set_ylabel('Number of CVEs')
# ax1.set_xlabel('Attack ID')

# # Rotate x-axis labels
# plt.xticks(rotation=90)

# # Line chart on secondary y-axis for Jaccard Similarity
# ax2 = ax1.twinx()
# ax2.plot(df.index, df["Jaccard"], color='green', label='Jaccard Index')
# ax2.set_ylabel('Jaccard Similarity')

# # Combine legends
# handles1, labels1 = ax1.get_legend_handles_labels()
# handles2, labels2 = ax2.get_legend_handles_labels()
# ax1.legend(handles1 + handles2, labels1 + labels2, loc='upper left')

# plt.title('Clustered Column-Line Chart with Secondary Y-axis')
# plt.tight_layout()
# plt.show()




# import pandas as pd
# import matplotlib.pyplot as plt

# # Sample data
# data = {
#     "TechID": ["T1003", "T1005", "T1007", "T1012", "T1014", "T1016", "T1018", "T1021", "T1027", "T1033", "T1039", "T1046", "T1049", "T1057", "T1080", "T1082", "T1083", "T1087", "T1092", "T1110", "T1111", "T1113", "T1115", "T1120", "T1123", "T1124", "T1125", "T1135", "T1176", "T1185", "T1211", "T1213", "T1217", "T1499", "T1528", "T1530", "T1534", "T1539", "T1554", "T1555", "T1566", "T1590", "T1598", "T1615", "T1620"],
#     "Intersection": [2, 26, 12, 6, 2, 10, 9, 5, 92, 14, 1, 7, 12, 7, 3, 8, 33, 12, 3, 14, 30, 7, 16, 13, 14, 11, 7, 12, 6, 30, 4, 2, 11, 39, 36, 2, 13, 124, 18, 2, 19, 11, 20, 10, 10],
#     "Union": [40, 88, 34, 23, 13, 26, 35, 32, 130, 35, 32, 41, 35, 27, 61, 37, 90, 29, 11, 53, 40, 20, 23, 20, 18, 22, 20, 40, 33, 110, 35, 6, 28, 57, 51, 5, 27, 151, 26, 17, 28, 32, 26, 20, 23],
#     "Jaccard": [0.05, 0.30, 0.35, 0.26, 0.15, 0.38, 0.26, 0.16, 0.71, 0.40, 0.03, 0.17, 0.34, 0.26, 0.05, 0.22, 0.37, 0.41, 0.27, 0.26, 0.75, 0.35, 0.70, 0.65, 0.78, 0.50, 0.35, 0.30, 0.18, 0.27, 0.11, 0.33, 0.39, 0.68, 0.71, 0.40, 0.48, 0.82, 0.69, 0.12, 0.68, 0.34, 0.77, 0.50, 0.43]
# }

# # Create DataFrame
# df = pd.DataFrame(data)

# # Set 'TechID' as index
# df.set_index('TechID', inplace=True)

# # Plot
# fig, ax1 = plt.subplots(figsize=(12, 6))

# # Clustered column chart for Intersection
# ax1.bar(df.index, df["Intersection"], width=0.4, color='blue', label=r'$\mathcal{L} \cap \mathcal{M}$')
# # Clustered column chart for Union
# ax1.bar(df.index, df["Union"], width=0.4, color='orange', label=r'$\mathcal{L} \cup \mathcal{M}$', alpha=0.5)
# ax1.set_ylabel('Number of CVEs')
# ax1.set_xlabel('Technique ID')


# # Rotate x-axis labels
# plt.xticks(rotation=90)

# # Line chart on secondary y-axis for Jaccard Similarity
# ax2 = ax1.twinx()
# ax2.plot(df.index, df["Jaccard"], color='green', label='Jaccard Index')
# ax2.set_ylabel('Jaccard Similarity')

# # Combine legends
# handles1, labels1 = ax1.get_legend_handles_labels()
# handles2, labels2 = ax2.get_legend_handles_labels()
# ax1.legend(handles1 + handles2, labels1 + labels2, loc='upper left')

# plt.title('Clustered Column-Line Chart with Secondary Y-axis')
# plt.tight_layout()
# plt.show()


# import pandas as pd
# import matplotlib.pyplot as plt

# # Sample data
# data = {
#     "Intersection": [2, 26, 12, 6, 2, 10, 9, 5, 92, 14, 1, 7, 12, 7, 3, 8, 33, 12, 3, 14, 30, 7, 16, 13, 14, 11, 7, 12, 6, 30, 4, 2, 11, 39, 36, 2, 13, 124, 18, 2, 19, 11, 20, 10, 10],
#     "Union": [40, 88, 34, 23, 13, 26, 35, 32, 130, 35, 32, 41, 35, 27, 61, 37, 90, 29, 11, 53, 40, 20, 23, 20, 18, 22, 20, 40, 33, 110, 35, 6, 28, 57, 51, 5, 27, 151, 26, 17, 28, 32, 26, 20, 23],
#     "Jaccard": [0.05, 0.30, 0.35, 0.26, 0.15, 0.38, 0.26, 0.16, 0.71, 0.40, 0.03, 0.17, 0.34, 0.26, 0.05, 0.22, 0.37, 0.41, 0.27, 0.26, 0.75, 0.35, 0.70, 0.65, 0.78, 0.50, 0.35, 0.30, 0.18, 0.27, 0.11, 0.33, 0.39, 0.68, 0.71, 0.40, 0.48, 0.82, 0.69, 0.12, 0.68, 0.34, 0.77, 0.50, 0.43]
# }

# # Create DataFrame
# df = pd.DataFrame(data)
# # Set 'TechID' as index
# # df.set_index('TechID', inplace=True)
# # Plot
# fig, ax1 = plt.subplots(figsize=(12, 6))

# # Clustered column chart for Intersection
# ax1.bar(df.index - 0.2, df["Intersection"], width=0.4, color='blue', label=r'$\mathcal{L} \cap \mathcal{M}$')
# # Clustered column chart for Union
# ax1.bar(df.index + 0.2, df["Union"], width=0.4, color='orange', label=r'$\mathcal{L} \cup \mathcal{M}$', alpha=0.5)
# # ax1.set_xlabel('Index')
# ax1.set_ylabel('Number of CVEs')
# ax1.set_xlabel('Techniuque ID')
# # Line chart on secondary y-axis for Jaccard Similarity
# ax2 = ax1.twinx()
# ax2.plot(df.index, df["Jaccard"], color='green', label='Jaccard Index')
# ax2.set_ylabel('Jaccard Similarity')

# # Combine legends
# handles1, labels1 = ax1.get_legend_handles_labels()
# handles2, labels2 = ax2.get_legend_handles_labels()
# ax1.legend(handles1 + handles2, labels1 + labels2, loc='upper left')

# plt.title('Clustered Column-Line Chart with Secondary Y-axis')
# plt.tight_layout()
# plt.show()



import pandas as pd
import matplotlib.pyplot as plt

# Sample data
data = {
    "Intersection": [2, 26, 12, 6, 2, 10, 9, 5, 92, 14, 1, 7, 12, 7, 3, 8, 33, 12, 3, 14, 30, 7, 16, 13, 14, 11, 7, 12, 6, 30, 4, 2, 11, 39, 36, 2, 13, 124, 18, 2, 19, 11, 20, 10, 10],
    "Union": [40, 88, 34, 23, 13, 26, 35, 32, 130, 35, 32, 41, 35, 27, 61, 37, 90, 29, 11, 53, 40, 20, 23, 20, 18, 22, 20, 40, 33, 110, 35, 6, 28, 57, 51, 5, 27, 151, 26, 17, 28, 32, 26, 20, 23],
    "Jaccard": [0.05, 0.30, 0.35, 0.26, 0.15, 0.38, 0.26, 0.16, 0.71, 0.40, 0.03, 0.17, 0.34, 0.26, 0.05, 0.22, 0.37, 0.41, 0.27, 0.26, 0.75, 0.35, 0.70, 0.65, 0.78, 0.50, 0.35, 0.30, 0.18, 0.27, 0.11, 0.33, 0.39, 0.68, 0.71, 0.40, 0.48, 0.82, 0.69, 0.12, 0.68, 0.34, 0.77, 0.50, 0.43]
}

# Create DataFrame
df = pd.DataFrame(data)

# Plot
fig, ax1 = plt.subplots(figsize=(12, 6))

# Scatter plot
sc = ax1.scatter(df["Intersection"], df["Union"], c=df["Jaccard"], cmap='viridis', label='Intersection vs Union')
ax1.set_xlabel('Intersection')
ax1.set_ylabel('Union')

# Create colorbar
cbar = plt.colorbar(sc)
cbar.set_label('Jaccard Similarity')

# Create secondary y-axis for Jaccard Similarity
ax2 = ax1.twinx()
ax2.set_ylabel('Jaccard Similarity')

# Combine legends
handles, labels = ax1.get_legend_handles_labels()
handles2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(handles + handles2, labels + labels2)

plt.title('Scatter Plot with Secondary Y-axis for Jaccard Similarity')
plt.tight_layout()
plt.show()


# Create DataFrame
df = pd.DataFrame(data)

# Plot
fig, ax1 = plt.subplots(figsize=(12, 6))

# Clustered column chart
ax1.bar(df.index, df["Intersection"], color='blue', label='Intersection')
ax1.bar(df.index, df["Union"], color='orange', label='Union', alpha=0.5)
ax1.set_xlabel('Index')
ax1.set_ylabel('Intersection / Union')

# Line chart on secondary y-axis for Jaccard Similarity
ax2 = ax1.twinx()
ax2.plot(df.index, df["Jaccard"], color='green', label='Jaccard Similarity')
ax2.set_ylabel('Jaccard Similarity')

# Combine legends
handles1, labels1 = ax1.get_legend_handles_labels()
handles2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(handles1 + handles2, labels1 + labels2, loc='upper left')

plt.title('Clustered Column-Line Chart with Secondary Y-axis')
plt.tight_layout()
plt.show()

# Create DataFrame
df = pd.DataFrame(data)

# Plot
fig, ax1 = plt.subplots(figsize=(12, 6))

# Clustered column chart for Intersection
ax1.bar(df.index - 0.2, df["Intersection"], width=0.4, color='blue', label='Intersection')
# Clustered column chart for Union
ax1.bar(df.index + 0.2, df["Union"], width=0.4, color='orange', label='Union', alpha=0.5)
ax1.set_xlabel('Index')
ax1.set_ylabel('Count')

# Line chart on secondary y-axis for Jaccard Similarity
ax2 = ax1.twinx()
ax2.plot(df.index, df["Jaccard"], color='green', label='Jaccard Similarity')
ax2.set_ylabel('Jaccard Similarity')
plt.xticks(range(0, len(data) + 0), [
    r'$\mathcal{L} \cap \mathcal{M}$',
    r'$\mathcal{L} \cup \mathcal{M}$',
    # r'$\mathcal{M}_{P} - \mathcal{L}_{P}$'
],fontsize=14)

# Combine legends
handles1, labels1 = ax1.get_legend_handles_labels()
handles2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(handles1 + handles2, labels1 + labels2, loc='upper left')

plt.title('Clustered Column-Line Chart with Secondary Y-axis')
plt.tight_layout()
plt.show()


import matplotlib.pyplot as plt

# Data
ground_truth = [0.40, 0.41, 0.63, 0.30, 0.29, 0.53, 0.47, 0.36, 0.73, 0.74, 
                1.00, 0.37, 0.63, 0.37, 0.43, 0.23, 0.39, 0.63, 0.60, 0.27,
                0.77, 0.41, 0.94, 0.68, 0.82, 0.58, 0.41, 0.33, 0.30, 0.81,
                0.12, 0.40, 0.58, 0.78, 0.92, 0.40, 0.50, 0.99, 0.95, 0.40,
                0.73, 0.58, 0.77, 0.53, 0.50]
detection = [0.05, 0.52, 0.44, 0.67, 0.25, 0.59, 0.36, 0.22, 0.96, 0.47,
             0.03, 0.24, 0.43, 0.47, 0.05, 0.80, 0.87, 0.55, 0.33, 0.88,
             0.97, 0.70, 0.73, 0.93, 0.93, 0.79, 0.70, 0.75, 0.32, 0.29,
             0.80, 0.67, 0.33, 0.39, 0.55, 0.75, 0.85, 0.75, 1.00, 0.93,
             0.83, 0.72, 0.14, 0.90, 0.46, 1.00, 0.91, 0.77]

jaccard = [0.05, 0.30, 0.35, 0.26, 0.15, 0.38, 0.26, 0.16, 0.71, 0.40,
           0.03, 0.17, 0.34, 0.26, 0.26, 0.22, 0.37, 0.41, 0.27, 0.26,
           0.75, 0.35, 0.70, 0.65, 0.78, 0.50, 0.35, 0.30, 0.18, 0.27,
           0.11, 0.33, 0.39, 0.68, 0.71, 0.40, 0.48, 0.82, 0.69, 0.12,
           0.68, 0.34, 0.77, 0.50, 0.43]

# Create scatter plot
plt.figure(figsize=(8, 6))
plt.scatter(ground_truth, detection, s=100, c=jaccard, cmap='viridis', alpha=0.75)
plt.colorbar(label='Jaccard Index')
plt.xlabel('Ground Truth')
plt.ylabel('Detection')
plt.title('Object Detection Performance')
plt.grid(True)
plt.show()

import seaborn as sns

# Data
# Assuming your data is stored in lists 'ground_truth', 'detection', and 'jaccard'



# # Scatter Plot
# plt.figure(figsize=(8, 6))
# sns.scatterplot(x=ground_truth, y=detection, hue=jaccard, palette='viridis', alpha=0.7)
# plt.xlabel('Ground Truth')
# plt.ylabel('Detection')
# plt.title('Scatter Plot of Ground Truth vs. Detection')
# plt.colorbar(label='Jaccard Index')
# plt.show()

# # Box Plot
# plt.figure(figsize=(8, 6))
# sns.boxplot(x=ground_truth, y=jaccard)
# plt.xlabel('Ground Truth')
# plt.ylabel('Jaccard Index')
# plt.title('Box Plot of Jaccard Index by Ground Truth')
# plt.show()

# # Line Plot
# plt.figure(figsize=(8, 6))
# plt.plot(range(len(jaccard)), jaccard, marker='o', linestyle='-', color='purple')
# plt.xlabel('Instance')
# plt.ylabel('Jaccard Index')
# plt.title('Line Plot of Jaccard Index over Dataset Instances')
# plt.show()

# # Density Plot
# plt.figure(figsize=(8, 6))
# sns.kdeplot(jaccard, color='orange', shade=True)
# plt.xlabel('Jaccard Index')
# plt.ylabel('Density')
# plt.title('Density Plot of Jaccard Index')
# plt.show()
