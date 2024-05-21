import numpy as np
import matplotlib.pyplot as plt
import random

true_predicted = np.array(
    [  6, 9, 1, 8, 7, 15, 1, 0, 9, 3, 2, 22, 6, 5, 16, 3, 7, 7, 4, 0, 8, 1, 1, 5, 6, 12, 6, 8, 26, 1, 0, 0, 2, 3, 16, 22, 9, 4, 5, 7, 10, 17, 10, 10, 3, 12, 5, 10, 10, 20, 1, 2, 8, 3, 3, 7, 12, 2, 6, 8, 2, 3, 9, 4, 6, 5, 19, 17, 14, 4, 2, 0, 6, 1, 19, 11, 8, 11, 8, 4, 5, 10, 29, 15, 4, 6, 20, 0, 34, 1, 33, 6, 0, 6
,57, 4, 55, 4, 30, 21, 4, 31, 21, 9, 6, 29, 71, 17, 4, 14, 1, 3, 9, 23
     ])
false_predicted = np.array(
    [ 26, 54, 1, 2, 65, 28, 19, 7, 60, 62, 5, 237, 103, 74, 35, 370, 71, 89, 17, 0, 102, 178, 1, 11, 25, 51, 60, 25, 69, 29, 15, 11, 152, 4, 234, 95, 179, 204, 69, 30, 99, 221, 308, 152, 22, 134, 86, 84, 235, 9, 23, 78, 252, 81, 120, 40, 75, 93, 15, 83, 8, 38, 74, 39, 65, 14, 59, 207, 9, 75, 109, 14, 17, 56, 242, 38, 97, 7, 92, 99, 28, 8, 155, 68, 76, 212, 45, 41, 16, 35, 22, 103, 32, 62
,116, 172, 271, 77, 46, 3, 219, 109, 75, 72, 167, 76, 186, 219, 81, 84, 0, 77, 44, 227
]
)

actual_values = np.array(
    [ 13, 16, 3, 28, 16, 22, 3, 5, 20, 26, 19, 26, 6, 6, 18, 3, 22, 19, 17, 16, 20, 1, 19, 19, 19, 19, 19, 19, 28, 2, 1, 1, 5, 8, 17, 30, 11, 7, 7, 7, 10, 17, 10, 10, 10, 19, 6, 14, 10, 23, 18, 7, 14, 7, 7, 19, 14, 7, 7, 9, 19, 19, 19, 19, 19, 23, 30, 19, 20, 5, 3, 1, 17, 1, 20, 19, 14, 13, 19, 20, 17, 10, 30, 21, 6, 6, 20, 7, 34, 3, 33, 6, 1, 7
,65, 4, 72, 7, 39, 27, 4, 44, 36, 10, 8, 31, 72, 25, 8, 20, 26, 28, 31, 30
])
predicted = true_predicted + false_predicted
print ((true_predicted))
print ((actual_values))


print ((true_predicted))
print ((actual_values))
plt.plot([min(actual_values), max(actual_values)], [min(actual_values), max(actual_values)], color='red', linestyle='--')

plt.scatter(actual_values, true_predicted, color='green', alpha=0.4)
plt.scatter(actual_values, false_predicted, color='blue', alpha=0.4)

plt.xlabel("Actual CVEs")
plt.ylabel("Predicted CVEs")
# plt.title("Actual vs. Predicted Values")
plt.show()