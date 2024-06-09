import matplotlib.pyplot as plt

# Provided data
threshold_values = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95]
precision_values = [
    0.375757576, 0.375757576, 0.375757576, 0.375757576, 0.375757576, 0.375757576, 
    0.375757576, 0.375757576, 0.36809816, 0.393103448, 0.495495495, 0.8, 
    0.92, 1, 1, 1, 1, 1, 1
]

recall_values = [
    1, 1, 1, 1, 1, 1, 1, 1, 0.967741935, 0.919354839, 0.887096774, 0.709677419, 
    0.370967742, 0.080645161, 0.016129032, 0, 0, 0, 0
]
# f1_values = [0.627906977, 0.627906977, 0.627906977, 0.627906977, 0.627906977, 0.627906977, 0.627906977, 0.627906977, 0.627906977, 0.631578947, 0.641509434, 0.676470588, 0.589473684, 0.376811594, 0.071428571, 0, 0, 0, 0]

# Plotting the Precision, Recall, and F1 using lines
plt.figure(figsize=(10, 6))
plt.plot(threshold_values, precision_values, label='Precision', linestyle='-')
plt.plot(threshold_values, recall_values, label='Recall', linestyle='-')
# plt.plot(threshold_values, f1_values, label='F1 Score', linestyle='-')



# Adding vertical lines at each threshold
# for threshold in threshold_values:
#     plt.axvline(x=threshold, linestyle='-', color='gray', alpha=0.5)
    
# Adding labels and title
plt.xlabel('Threshold')
plt.ylabel('Score')
# plt.title('Precision, Recall, and F1 Score')
plt.legend()
plt.grid(True)

# Specify the x-axis ticks
plt.xticks(threshold_values)

# Save the plot as a PDF file
plt.savefig('precision_recall_f1_plot.pdf')

# Show the plot
plt.show()

# import matplotlib.pyplot as plt

# # False Match Rate (FMR) and False Non-Match Rate (FNMR) values
# FMR = [1, 1, 1, 1, 1, 1, 1, 1, 1, 0.984375, 0.84375, 0.5625, 0.203125, 0.03125, 0, 0, 0, 0, 0, 0]
# FNMR = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0.055555556, 0.148148148, 0.481481481, 0.759259259, 0.962962963, 1, 1, 1, 1, 1]
# threshold_values = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95, 100]  # Adjusted to match the dimensions

# # Plotting the graph
# plt.plot(threshold_values, FMR, label='False Match Rate (FMR)', linestyle='-')
# plt.plot(threshold_values, FNMR, label='False Non-Match Rate (FNMR)', linestyle='-')

# # Adding labels and title
# plt.xlabel('Threshold')
# plt.ylabel('Rate')
# # plt.title('FMR and FNMR vs Threshold')

# # Adding legend
# plt.legend()
# # Specify the x-axis ticks
# plt.xticks(threshold_values)
# # Display the plot
# plt.grid(True)
# plt.show()
