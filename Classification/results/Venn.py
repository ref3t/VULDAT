import matplotlib.pyplot as plt

# Given data
L_intersect_M = [2, 26, 12, 6, 2, 10, 9, 5, 92, 14, 1, 7, 12, 7, 3, 8, 33, 12, 3, 14, 30, 7, 16, 13, 14, 11, 7, 12, 6, 30, 4, 2, 11, 39, 36, 2, 13, 124, 18, 2, 19, 11, 20, 10, 10]
L_sum = [37, 50, 27, 9, 8, 17, 25, 23, 96, 30, 32, 29, 28, 15, 57, 10, 38, 22, 9, 16, 31, 10, 22, 14, 15, 14, 10, 16, 19, 103, 5, 3, 20, 46, 48, 2, 14, 150, 25, 14, 21, 24, 20, 11, 13]
M = [5, 64, 19, 20, 7, 19, 19, 14, 126, 19, 1, 19, 19, 19, 7, 35, 85, 19, 5, 51, 39, 17, 17, 19, 17, 19, 17, 36, 20, 37, 34, 5, 19, 50, 39, 5, 26, 125, 19, 5, 26, 19, 26, 19, 20]

# Calculate Jaccard index for each pair
jaccard_indices = [L_intersect / (L + M - L_intersect) for L_intersect, L, M in zip(L_intersect_M, L_sum, M)]

# Create box plot
plt.boxplot(jaccard_indices)
plt.title('Box plot of Jaccard index')
plt.xlabel('Jaccard index')
plt.show()
