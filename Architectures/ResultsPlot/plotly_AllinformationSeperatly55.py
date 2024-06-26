

import matplotlib.pyplot as plt
import pandas as pd

data_just_proc = [
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.8, 0.017241379, 0.033755274],
    [0.5, 0.024390244, 0.046511628],
    [0.666666667, 0.065217391, 0.118811881],
    [0.833333333, 0.021929825, 0.042735043],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.6875, 0.057894737, 0.106796117],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.333333333, 0.004405286, 0.008695652],
    [0.65, 0.1015625, 0.175675676],
    [0.625, 0.054945055, 0.101010101],
    [0.5, 0.045685279, 0.08372093],
    [0.111111111, 0.157894737, 0.130434783],
    [0.424242424, 0.157303371, 0.229508197],
    [1, 0.003484321, 0.006944444],
    #[0, 0, '#DIV/0!'],
    [0.75862069, 0.068965517, 0.126436782],
    [0.357142857, 0.032894737, 0.060240964],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    [0.157894737, 0.057692308, 0.084507042],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.022522523, 0.044052863],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.913043478, 0.152173913, 0.260869565],
    [0.8, 0.022222222, 0.043243243],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.009259259, 0.018348624],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.418181818, 0.105022831, 0.167883212],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.003690037, 0.007352941],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.006024096, 0.011976048],
    [0.567567568, 0.098130841, 0.167330677],
    #[0, 0, '#DIV/0!'],
    [1, 0.015974441, 0.031446541],
    [0.6, 0.260869565, 0.363636364],
    [1, 0.009933775, 0.019672131],
    #[0, 0, '#DIV/0!'],
    [0.75, 0.071428571, 0.130434783],
    #[0, 0, '#DIV/0!'],
    [0.315789474, 0.116504854, 0.170212766],
    [0.666666667, 0.00862069, 0.017021277],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.333333333, 0.036585366, 0.065934066],
    [1, 0.026490066, 0.051612903],
    [0.6, 0.025104603, 0.048192771],
    [0.75, 0.065217391, 0.12],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.8, 0.015503876, 0.030418251],
    [1, 0.052631579, 0.1],
    #[0, 0, '#DIV/0!'],
    [0.555555556, 0.098039216, 0.166666667],
    #[0, 0, '#DIV/0!'],
    [0.333333333, 0.00952381, 0.018518519],
    [1, 0.003355705, 0.006688963],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [0.125, 0.115384615, 0.12],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.440860215, 0.251533742, 0.3203125],
    [0.3, 0.164835165, 0.212765957],
    [1, 0.02739726, 0.053333333],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [1, 0.047619048, 0.090909091],
    [0.2, 0.038461538, 0.064516129],
    [0.25, 0.0078125, 0.015151515],
    [0.111111111, 0.090909091, 0.1],
    [0.230769231, 0.111111111, 0.15],
    [0.25, 0.019230769, 0.035714286],
    [0.5, 0.004132231, 0.008196721],
    [0.5, 0.003278689, 0.006514658],
    [1, 0.010989011, 0.02173913],
    [0.183333333, 0.275, 0.22],
    [0.833333333, 0.01618123, 0.031746032],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.044444444, 0.081632653],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.466666667, 0.048951049, 0.088607595],
    [0.444444444, 0.068965517, 0.119402985],
    [0.555555556, 0.023584906, 0.045248869],
    [1, 0.008902077, 0.017647059],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.762711864, 0.155172414, 0.257879656],
    [0.666666667, 0.044444444, 0.083333333],
    [0.222222222, 0.020618557, 0.037735849],
    [0.916666667, 0.093220339, 0.169230769],
    [1, 0.004048583, 0.008064516],
    [0.5, 0.010989011, 0.021505376],
    [0.5, 0.0625, 0.111111111],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.02],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.588235294, 0.064102564, 0.115606936],
    [1, 0.010204082, 0.02020202],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.25, 0.038461538, 0.066666667],
    [1, 0.125, 0.222222222],
    [0.25, 0.038461538, 0.066666667],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.357142857, 0.042016807, 0.07518797],
    #[0, 0, '#DIV/0!'],
    [0.25, 0.088888889, 0.131147541],
    [0.727272727, 0.064, 0.117647059],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.25, 0.038461538, 0.066666667],
    [0.4, 0.015151515, 0.02919708],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.333333333, 0.128712871, 0.185714286],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [0.555555556, 0.096153846, 0.163934426],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    [0.75, 0.016574586, 0.032432432],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    [0.166666667, 0.015384615, 0.028169014],
    [1, 0.003676471, 0.007326007],
    [0.111111111, 0.009433962, 0.017391304],
    [0.5, 0.090517241, 0.153284672],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.105263158, 0.173913043],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.565217391, 0.180555556, 0.273684211],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [0.714285714, 0.02283105, 0.044247788],
    [0.428571429, 0.088235294, 0.146341463],
    [0.5, 0.005780347, 0.011428571],
    [1, 0.125, 0.222222222],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.571428571, 0.102564103, 0.173913043],
    [0.363636364, 0.058823529, 0.101265823],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.016949153, 0.033333333],
    [1, 0.013605442, 0.026845638],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [1, 0.027777778, 0.054054054],
    [0.65, 0.152941176, 0.247619048],
    [1, 0.011764706, 0.023255814],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.2, 0.023809524, 0.042553191],
    [0.5, 0.04, 0.074074074],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.017094017, 0.033613445],
    [0.5, 0.072289157, 0.126315789],
    [0.111111111, 0.02, 0.033898305],
    [0.4, 0.285714286, 0.333333333],
    #[0, 0, '#DIV/0!'],
    [0.5, 0.058823529, 0.105263158],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.3, 0.428571429, 0.352941176],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.25, 0.368421053, 0.29787234],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [1, 0.01980198, 0.038834951],
    [1, 0.085714286, 0.157894737],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
#['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.384615385, 0.133333333, 0.198019802],
    [0.4, 0.029850746, 0.055555556],
    [0.333333333, 0.166666667, 0.222222222],
    [0.769230769, 0.153846154, 0.256410256],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.034722222, 0.067114094],
    [0.6, 0.018072289, 0.035087719],
    [0.166666667, 0.02, 0.035714286],
    [0.555555556, 0.034722222, 0.065359477],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    [1, 0.015384615, 0.03030303],
    [1, 0.032520325, 0.062992126],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.010810811, 0.021390374],
    [0.166666667, 0.157894737, 0.162162162],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    [1, 0.057142857, 0.108108108],
    [0.5, 0.052631579, 0.095238095],
    [0.333333333, 0.017857143, 0.033898305],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],
    [1, 0.052631579, 0.1],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.01980198, 0.038834951],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.00617284, 0.012269939],
    [0.1875, 0.029126214, 0.050420168],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.018072289, 0.035502959],
    [0.5, 0.011695906, 0.022857143],
    [1, 0.005847953, 0.011627907],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.75, 0.142857143, 0.24],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    [0.5, 0.142857143, 0.222222222],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.444444444, 0.12, 0.188976378],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [0.321428571, 0.064285714, 0.107142857],
    [1, 0.011494253, 0.022727273],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.02994012, 0.058139535],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.012345679, 0.024390244],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.058823529, 0.111111111],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.092783505, 0.169811321],
    [1, 0.027777778, 0.054054054],
    [0.057142857, 0.022988506, 0.032786885],
    [0.375, 0.073770492, 0.123287671],
    #[0, 0, '#DIV/0!'],
    [0.6, 0.020979021, 0.040540541],
    [0.9, 0.257142857, 0.4],
    [0.909090909, 0.166666667, 0.281690141],
    [0.272727273, 0.428571429, 0.333333333],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.944444444, 0.098837209, 0.178947368],
    [1, 0.01980198, 0.038834951],
    [1, 0.005464481, 0.010869565],
    [1, 0.033898305, 0.06557377],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.933333333, 0.254545455, 0.4],
    [0.444444444, 0.028571429, 0.053691275],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.015384615, 0.029850746],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.0078125, 0.015384615],
    [1, 0.007575758, 0.015037594],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.551724138, 0.142222222, 0.22614841],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.65, 0.057522124, 0.105691057],
    [0.142857143, 0.028571429, 0.047619048],
    [0.3125, 0.034722222, 0.0625],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.529411765, 0.0625, 0.111801242],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.85, 0.485714286, 0.618181818],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.008474576, 0.016806723],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [0.016393443, 0.142857143, 0.029411765],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.833333333, 0.046728972, 0.088495575],
    [1, 0.005988024, 0.011904762],
    [0.9375, 0.148514851, 0.256410256],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.004016064, 0.008],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.571428571, 0.019704433, 0.038095238],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.013793103, 0.026845638],
    [1, 0.006849315, 0.013605442],
    [1, 0.023809524, 0.046511628],
    [0.5, 0.018181818, 0.035087719],
    [0.5, 0.006024096, 0.011904762],
    [0.9375, 0.144230769, 0.25],
    [0.416666667, 0.119047619, 0.185185185],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.085714286, 0.157894737],
    [1, 0.01242236, 0.024539877],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.008196721, 0.016260163],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.050847458, 0.096774194],
    [1, 0.114285714, 0.205128205],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.210526316, 0.102564103, 0.137931034],
    [0.611111111, 0.063953488, 0.115789474],
    [1, 0.004065041, 0.008097166],
    [0.375, 0.071428571, 0.12],
    [0.65, 0.060465116, 0.110638298],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.017094017, 0.033613445],
    [0.892857143, 0.073313783, 0.135501355],
    [0.6, 0.1, 0.171428571],
    [1, 0.004255319, 0.008474576],
    [0.318181818, 0.179487179, 0.229508197],
    [0.866666667, 0.25, 0.388059701],
    [1, 0.008474576, 0.016806723],
    [1, 0.04950495, 0.094339623],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.470588235, 0.097560976, 0.161616162],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.090909091, 0.714285714, 0.161290323],
    [1, 0.117647059, 0.210526316],
    [1, 0.033088235, 0.06405694],
    [0.875, 0.050724638, 0.095890411],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.666666667, 0.008928571, 0.017621145],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.409090909, 0.107142857, 0.169811321],
    [1, 0.016949153, 0.033333333],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.016042781, 0.031578947],
    [0.714285714, 0.172413793, 0.277777778],
    [0.307692308, 0.032786885, 0.059259259],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.008695652, 0.017241379],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.8, 0.04, 0.076190476],
    [0.75, 0.054216867, 0.101123596],
    [1, 0.02, 0.039215686],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [1, 0.004784689, 0.00952381],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.36, 0.105882353, 0.163636364],
    [0.413793103, 0.062827225, 0.109090909],
    [0.294117647, 0.050505051, 0.086206897],
    #[0, 0, '#DIV/0!'],
    [1, 0.030769231, 0.059701493],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.047297297, 0.086419753],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.018867925, 0.037037037],
    [0.722222222, 0.053061224, 0.098859316],
    [0.5, 0.006622517, 0.013071895],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.008695652, 0.017241379],
    [0.5, 0.028571429, 0.054054054],
    #[0, 0, '#DIV/0!'],
    [0.411764706, 0.205882353, 0.274509804],
    [1, 0.025862069, 0.050420168],
    [0.515151515, 0.077625571, 0.134920635],
    [0.038461538, 0.005464481, 0.009569378],
    [0.5, 0.01, 0.019607843],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.166666667, 0.047619048, 0.074074074],
    [0.195121951, 0.111111111, 0.14159292],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.157894737, 0.272727273],
    [0.5, 0.142857143, 0.222222222],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [0.357142857, 0.028409091, 0.052631579],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.069767442, 0.130434783],
    #[0, 0, '#DIV/0!'],
    [0.875, 0.333333333, 0.482758621],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.75, 0.058252427, 0.108108108],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.009389671, 0.018604651],
    #[0, 0, '#DIV/0!'],
    [1, 0.005464481, 0.010869565],
    [0.424242424, 0.111111111, 0.176100629],
    #[0, 0, '#DIV/0!'],
    [0.5, 0.02247191, 0.043010753],
    [0.5, 0.023529412, 0.04494382],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.020725389, 0.040609137],
    [0.222222222, 0.018518519, 0.034188034],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.6, 0.033707865, 0.063829787],
    [1, 0.00462963, 0.00921659],
    [1, 0.019230769, 0.037735849],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.6, 0.013888889, 0.027149321],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.769230769, 0.087719298, 0.157480315],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.01, 0.01980198],
    [0.6875, 0.0859375, 0.152777778],
    [0.4, 0.014705882, 0.028368794],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.003861004, 0.007692308],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.7, 0.2, 0.311111111],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.666666667, 0.057142857, 0.105263158],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.007017544, 0.013937282],
    [0.454545455, 0.029239766, 0.054945055],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.017964072, 0.035294118],
    [0.551724138, 0.098765432, 0.167539267],
    [1, 0.005524862, 0.010989011],
    [0.6, 0.038961039, 0.073170732],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.28, 0.055555556, 0.092715232],
    [0.569444444, 0.251533742, 0.34893617],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.15, 0.055555556, 0.081081081],
    [0.176470588, 0.050420168, 0.078431373],
    [0.545454545, 0.077419355, 0.13559322],
    [1, 0.005, 0.009950249],
    [0.988235294, 0.358974359, 0.526645768],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.666666667, 0.046511628, 0.086956522],
    [0.258064516, 0.040609137, 0.070175439],
    [1, 0.006666667, 0.013245033],
    [0.5, 0.15625, 0.238095238],
    [0.2, 0.010989011, 0.020833333],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [0.4, 0.013888889, 0.026845638],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.363636364, 0.026315789, 0.049079755],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.1, 0.035714286, 0.052631579],
    [1, 0.010204082, 0.02020202],
    [0.692307692, 0.109756098, 0.189473684],
    [0.846153846, 0.06626506, 0.122905028],
    [0.5, 0.013605442, 0.026490066],
    #[0, 0, '#DIV/0!'],
    [0.6, 0.011811024, 0.023166023],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.014285714, 0.027777778],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.014134276, 0.027874564],
    [0.357142857, 0.131578947, 0.192307692],
    [1, 0.011976048, 0.023668639],
    [0.5, 0.003521127, 0.006993007],
    #[0, 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.333333333, 0.052631579, 0.090909091],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.333333333, 0.020408163, 0.038461538],
    #[0, 0, '#DIV/0!'],
    [0.536585366, 0.093617021, 0.15942029],
    [0.333333333, 0.009615385, 0.018691589],
    [1, 0.192307692, 0.322580645],
    #[0, 0, '#DIV/0!'],
    [1, 0.006944444, 0.013793103],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.884615385, 0.112195122, 0.199134199],
    [1, 0.031055901, 0.060240964],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.421052632, 0.066115702, 0.114285714],
    #[0, 0, '#DIV/0!'],
    [0.107142857, 0.028846154, 0.045454545],
    [0.583333333, 0.037634409, 0.070707071],
    [0.666666667, 0.022222222, 0.043010753],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [1, 0.022222222, 0.043478261],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.170731707, 0.095890411, 0.122807018],
    [0.777777778, 0.042682927, 0.080924855],
    [0.3, 0.023809524, 0.044117647],
    [0.4, 0.01980198, 0.037735849],
    [1, 0.006024096, 0.011976048],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    [0.5, 0.058823529, 0.105263158],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.428571429, 0.023255814, 0.044117647],
    [1, 0.015384615, 0.03030303],
    [1, 0.01980198, 0.038834951],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.666666667, 0.077922078, 0.139534884],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.777777778, 0.034653465, 0.066350711],
    [0.666666667, 0.008695652, 0.017167382],
    [0.8, 0.020725389, 0.04040404],
    [0.8, 0.043956044, 0.083333333],
    [0.5, 0.022222222, 0.042553191],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.006944444, 0.01369863],
    [0.428571429, 0.017857143, 0.034285714],
    [0.272727273, 0.017964072, 0.033707865],
    #[0, 0, '#DIV/0!'],
    [0.5, 0.009569378, 0.018779343],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.777777778, 0.134615385, 0.229508197],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.003952569, 0.007874016],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.382352941, 0.126213592, 0.189781022],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.052631579, 0.1],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.75, 0.012552301, 0.024691358],
    [0.666666667, 0.00952381, 0.018779343],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.016260163, 0.031496063],
    [0.909090909, 0.058139535, 0.109289617],
    #[0, 0, '#DIV/0!'],
    [0.941176471, 0.094117647, 0.171122995],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.075630252, 0.131386861],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.111111111, 0.004901961, 0.009389671],
    [0.5, 0.005291005, 0.010471204],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.928571429, 0.029345372, 0.056892779],
    [0.714285714, 0.025906736, 0.05],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.012195122, 0.023809524],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.9, 0.031141869, 0.060200669],
    [1, 0.014778325, 0.029126214],
    #[0, 0, '#DIV/0!'],
    [0.333333333, 0.004132231, 0.008163265],
    [1, 0.016666667, 0.032786885],
    [0.823529412, 0.111553785, 0.196491228],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.710526316, 0.114893617, 0.197802198],
    [1, 0.004149378, 0.008264463],
    [1, 0.011111111, 0.021978022],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.214285714, 0.044117647, 0.073170732],
    [1, 0.005181347, 0.010309278],
    #['#DIV/0!', 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.703703704, 0.122580645, 0.208791209],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.142857143, 0.013888889, 0.025316456],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.006896552, 0.01369863],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.01183432, 0.023391813],
    [0.454545455, 0.101010101, 0.165289256],
    [0.5, 0.010204082, 0.02],
    [0.307692308, 0.03960396, 0.070175439],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.010471204, 0.020725389],
    [0.333333333, 0.005376344, 0.010582011],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.095238095, 0.048780488, 0.064516129],
    [1, 0.005128205, 0.010204082],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.272727273, 0.018072289, 0.033898305],
    #[0, 0, '#DIV/0!'],
    [0.5, 0.038709677, 0.071856287],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.8, 0.024539877, 0.047619048],
    [0.333333333, 0.024390244, 0.045454545],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.0078125, 0.015503876],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.789473684, 0.071428571, 0.131004367],
    [0.833333333, 0.051020408, 0.096153846],
    [0.666666667, 0.011627907, 0.022857143],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.666666667, 0.020408163, 0.03960396],
    [0.684210526, 0.103174603, 0.179310345],
    #[0, 0, '#DIV/0!'],
    [0.235294118, 0.043956044, 0.074074074],
    [0.555555556, 0.055555556, 0.101010101],
    [0.565217391, 0.080745342, 0.141304348],
    [0.5, 0.011904762, 0.023255814],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.2, 0.005291005, 0.010309278],
    [1, 0.011764706, 0.023255814],
    [0.5, 0.023809524, 0.045454545],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.007751938, 0.015267176],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [0.5, 0.010204082, 0.02],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    [0.294117647, 0.02994012, 0.054347826],
    [1, 0.023255814, 0.045454545],
    [0.5, 0.035294118, 0.065934066],
    [1, 0.003937008, 0.007843137],
    [0.5, 0.003816794, 0.007575758],
    [0.4, 0.010204082, 0.019900498],
    [1, 0.004716981, 0.009389671],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.034965035, 0.065359477],
    [1, 0.008474576, 0.016806723],
    [1, 0.011560694, 0.022857143],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.75, 0.063829787, 0.117647059],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.5, 0.103174603, 0.171052632],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [1, 0.006944444, 0.013793103],
    [1, 0.00462963, 0.00921659],
    [0.5, 0.161290323, 0.243902439],
]

data_techniques_without_sub = [
    [0.034482759, 0.2, 0.058823529],
    [0.714285714, 0.15625, 0.256410256],
    [0.555555556, 0.263157895, 0.357142857],
    ##[0, 0, '#DIV/0!'],  # Commented line
    [0.666666667, 0.285714286, 0.4],
    [0.55, 0.578947368, 0.564102564],
    [0.363636364, 0.210526316, 0.266666667],
    [0.16, 0.571428571, 0.25],
    [0.911764706, 0.492063492, 0.639175258],
    [0.571428571, 0.421052632, 0.484848485],
    [0.052631579, 1, 0.1],
    [0.212121212, 0.368421053, 0.269230769],
    [0.666666667, 0.631578947, 0.648648649],
    [0.666666667, 0.526315789, 0.588235294],
    [0.625, 0.263157895, 0.37037037],
    ##[0, 0, '#DIV/0!'],  # Commented line
    [0.444444444, 0.571428571, 0.5],
    [0.818181818, 0.257142857, 0.391304348],
    [0.8125, 0.152941176, 0.257425743],
    [0.625, 0.526315789, 0.571428571],
    ##[0, 0, '#DIV/0!'],  # Commented line
    [0.564102564, 0.431372549, 0.488888889],
    [0.625, 0.769230769, 0.689655172],
    [1, 0.235294118, 0.380952381],
    [1, 0.588235294, 0.740740741],
    [0.142857143, 0.2, 0.166666667],
    ##[0, 0, '#DIV/0!'],  # Commented line
    [1, 0.647058824, 0.785714286],
    [0.777777778, 0.736842105, 0.756756757],
    [1, 0.588235294, 0.740740741],
    [0.739130435, 0.472222222, 0.576271186],
    [0.125, 0.05, 0.071428571],
    [0.208860759, 0.891891892, 0.338461538],
    [0.766666667, 0.851851852, 0.807017544],
    [0.222222222, 0.352941176, 0.272727273],
    #[#DIV/0!, 0, '#DIV/0!'],  # Commented line
    [0.666666667, 0.315789474, 0.428571429],
    ##[0, 0, '#DIV/0!'],  # Commented line
    # #[0, '#DIV/0!', '#DIV/0!'],  # Commented line
    [0.597222222, 0.86, 0.704918033],
    [0.44047619, 0.948717949, 0.601626016],
    [1, 0.4, 0.571428571],
    #[#DIV/0!, 0, '#DIV/0!'],  # Commented line
    [0.836879433, 0.944, 0.887218045],
    [0.421052632, 0.421052632, 0.421052632],
    [0.034482759, 0.2, 0.058823529],
    [1, 0.5, 0.666666667],
    # #[0, '#DIV/0!', '#DIV/0!'],
    [0.5, 0.076923077, 0.133333333],
    [0.592592593, 0.842105263, 0.695652174],
    [0.703703704, 0.826086957, 0.76],
    #[#DIV/0!, #DIV/0!, '#DIV/0!'],  # Commented line
    #[#DIV/0!, 0, '#DIV/0!'],  # Commented line
    ##[0, '#DIV/0!', '#DIV/0!'],  # Commented line
    [0.066666667, 1, 0.125],
    [0.333333333, 0.157894737, 0.214285714],
    [0.166666667, 0.05, 0.076923077]
]


data_subtechniques_without_tech =[
    ##[0, 0, '#DIV/0!'],  # Commented line
    [0.407407407, 0.785714286, 0.536585366],
    ##[0, 0, '#DIV/0!'],  # Commented line
    [0.012820513, 1, 0.025316456],
    [0.727272727, 0.872727273, 0.79338843],
    [0.725490196, 0.587301587, 0.649122807],
    [0.788461538, 0.759259259, 0.773584906],
    [1, 0.5, 0.666666667],
    [0.615384615, 0.421052632, 0.5],
    [0.5, 1, 0.666666667],
    [0.071428571, 0.333333333, 0.117647059],
    ##[0, 0, '#DIV/0!'],  # Commented line
    [0.210526316, 0.571428571, 0.307692308],
    [0.263157895, 1, 0.416666667],
    [0.181818182, 0.75, 0.292682927],
    [0.333333333, 1, 0.5],
    [0.159090909, 0.368421053, 0.222222222],
    [0.387096774, 0.857142857, 0.533333333],
    [0.75, 0.666666667, 0.705882353],
    [0.3, 0.857142857, 0.444444444],
    ##[0, 0, '#DIV/0!'],  # Commented line
    # #[0, '#DIV/0!', '#DIV/0!'],  # Commented line
    # #[0, '#DIV/0!', '#DIV/0!'],  # Commented line
    # #[0, '#DIV/0!', '#DIV/0!'],  # Commented line
    # #[0, '#DIV/0!', '#DIV/0!'],  # Commented line
    # #[0, '#DIV/0!', '#DIV/0!'],  # Commented line
    # #[0, '#DIV/0!', '#DIV/0!'],  # Commented line
    [0.383333333, 0.851851852, 0.528735632],
    [0.7, 0.233333333, 0.35],
    [0.230769231, 0.6, 0.333333333],
    #[#DIV/0!, 0, '#DIV/0!'],  # Commented line
    [0.151515152, 0.263157895, 0.192307692],
    [0.045454545, 0.05, 0.047619048],
    #[#DIV/0!, 0, '#DIV/0!'],  # Commented line
    [0.526315789, 0.694444444, 0.598802395],
    ##[0, 0, '#DIV/0!'],  # Commented line
    [0.676470588, 0.8625, 0.758241758],
    [0.179487179, 1, 0.304347826],
    [0.057692308, 0.75, 0.107142857],
    [0.9, 0.642857143, 0.75],
    [0.1, 0.428571429, 0.162162162],
    [0.216216216, 1, 0.355555556],
    [0.8875, 0.731958763, 0.802259887],
    [0.272727273, 0.857142857, 0.413793103],
    [0.466666667, 1, 0.636363636],
    [0.275862069, 1, 0.432432432],
    [0.333333333, 0.142857143, 0.2],
    [0.979166667, 0.854545455, 0.912621359],
    [0.846153846, 0.666666667, 0.745762712],
    [1, 0.038461538, 0.074074074],
    ##[0, 0, '#DIV/0!'],  # Commented line
    # #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.525, 0.954545455, 0.677419355],
    [0.535714286, 0.652173913, 0.588235294],
    #[#DIV/0!, 0, '#DIV/0!'],  # Commented line
    #[#DIV/0!, 0, '#DIV/0!'],  # Commented line
    #[#DIV/0!, 0, '#DIV/0!'],  # Commented line
]
data_tactic =[
    # #[0, 0, '#DIV/0!'],  # Commented line
    # [#DIV/0!, 0, '#DIV/0!'],  # Commented line
    [0.727272727, 0.059479554, 0.109965636],
    [0.961538462, 0.099206349, 0.179856115],
    #[#DIV/0!, 0, '#DIV/0!'],  # Commented line
    #[#DIV/0!, 0, '#DIV/0!'],  # Commented line
    ##[0, 0, '#DIV/0!'],  # Commented line
    #[#DIV/0!, 0, '#DIV/0!'],  # Commented line
    [0.5, 0.012048193, 0.023529412],
    #[#DIV/0!, 0, '#DIV/0!'],  # Commented line
    [1, 0.032786885, 0.063492063]
]


Capec_data = [[0.020833333, 0.25, 0.038461538],
    #['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    #[0, 0, '#DIV/0!'],
    [0.125, 0.025641026, 0.042553191],
    #[0, 0, '#DIV/0!'],
    [0.24, 0.052631579, 0.086330935],
    [0.047619048, 0.018181818, 0.026315789],
    [0.214285714, 0.068181818, 0.103448276],
    [0.233333333, 0.7, 0.35],
    [0.038461538, 0.125, 0.058823529],
    #[0, 0, '#DIV/0!'],
    [1, 0.038461538, 0.074074074],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    ##['#DIV/0!', 0, '#DIV/0!'],  # Commented line
    [0.526315789, 0.454545455, 0.487804878],
    #[0, 0, '#DIV/0!'],
    [0.0625, 0.05, 0.055555556],
    #[0, 0, '#DIV/0!'],
    ##['#DIV/0!', 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    [0.272727273, 0.136363636, 0.181818182],
    #[0, 0, '#DIV/0!'],
    ##['#DIV/0!', 0, '#DIV/0!'],
    [0.434782609, 0.153846154, 0.227272727],
    [0.016393443, 1, 0.032258065],
    [1, 0.052631579, 0.1],
    [0.785714286, 0.578947368, 0.666666667],
    [0.222222222, 0.105263158, 0.142857143],
    [0.5, 0.157894737, 0.24],
    [0.181818182, 0.105263158, 0.133333333],
    [0.25, 0.052631579, 0.086956522],
    #[0, 0, '#DIV/0!'],
    ##['#DIV/0!', 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],
    [0.126984127, 0.148148148, 0.136752137],
    [0.039473684, 0.272727273, 0.068965517],
    [0.227272727, 0.714285714, 0.344827586],
    [0.111111111, 0.142857143, 0.125],
    [0.057142857, 0.235294118, 0.091954023],
    [0.222222222, 0.210526316, 0.216216216],
    [0.045454545, 0.166666667, 0.071428571],
    [0.45, 0.642857143, 0.529411765],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    [0.058823529, 0.142857143, 0.083333333],
    #[0, 0, '#DIV/0!'],
    [0.153846154, 0.285714286, 0.2],
    #[0, 0, '#DIV/0!'],
    [0.19047619, 0.888888889, 0.31372549],
    [1, 0.052631579, 0.1],
    [0.25, 0.052631579, 0.086956522],
    [0.285714286, 0.210526316, 0.242424242],
    [0.5, 0.052631579, 0.095238095],
    [0.3125, 0.263157895, 0.285714286],
    #[0, 0, '#DIV/0!'],
    [0.75, 0.130434783, 0.222222222],
    #[0, 0, '#DIV/0!'],
    [0.204545455, 0.473684211, 0.285714286],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #['#DIV/0!', 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    [0.666666667, 0.315789474, 0.428571429],
    [0.8, 0.111111111, 0.195121951],
    [0.263157895, 0.263157895, 0.263157895],
    [0.111111111, 0.1, 0.105263158],
    [0.125, 0.058823529, 0.08],
    [0.666666667, 0.6, 0.631578947],
    [0.263157895, 0.5, 0.344827586],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    #[0, 0, '#DIV/0!'],
    [0.090909091, 0.076923077, 0.083333333],
    #[0, 0, '#DIV/0!'],
]
import plotly.express as px
import pandas as pd

labels = ["Precision", "Recall", "F1 Score"]
print(len(data_just_proc))
print(len(data_techniques_without_sub))
print(len(data_subtechniques_without_tech))
df1 = pd.DataFrame(data_just_proc, columns=labels)
df3 = pd.DataFrame(data_techniques_without_sub, columns=labels)
df4 = pd.DataFrame(data_subtechniques_without_tech, columns=labels)
df5 = pd.DataFrame(data_tactic, columns=labels)
df6 = pd.DataFrame(Capec_data, columns=labels)



# combined_df = pd.concat([df1, df3, df4,df5,df6], ignore_index=True)
# combined_df["ATT&CK Information"] =["All Tactics"] * len(df5) + ["All Techniques"] * len(df3) + ["All Sub-Techniques"] * len(df4)+ ["All Procedures"] * len(df1)+ ["All CAPECs"] * len(df6) 
combined_df = pd.concat([ df5,df3,df4,df1,df6], ignore_index=True)
combined_df["ATT&CK Information"] =["All Tactics"] * len(df5) +["All Techniques"] * len(df3)  + ["All Sub-Techniques"] * len(df4)+ ["All Procedures"] * len(df1)+ ["All CAPECs"] * len(df6) 

melted_df = pd.melt(combined_df, id_vars=["ATT&CK Information"], value_vars=labels, var_name="Metric", value_name="Value")

fig = px.box(melted_df, x="Metric", y="Value", color="ATT&CK Information", color_discrete_sequence=["black", "dimgrey", "darkgrey", "slategrey"])
fig.update_layout(
    title="Combined Box Plot for Metrics",
    xaxis_title="Metric",
    yaxis_title="Value",
    plot_bgcolor="white",
    paper_bgcolor="white"
)

# Add x-axis label
fig.update_xaxes(title_text="Metrics")

# Add y-axis label
fig.update_yaxes(title_text="Metric Values")

# Add mean indicator
fig.update_traces(boxmean=True)
fig.show()
