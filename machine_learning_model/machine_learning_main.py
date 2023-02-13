from flask import Blueprint, jsonify, render_template, redirect, flash, request, make_response
import numpy
from scipy import stats
import matplotlib.pyplot as plt

ml = Blueprint('machine_learning_main', __name__)


# Linear regression
# @ml.route('/machine-learning/', methods=['GET'])
# def machine_learning():
#     # x = age
#     # y = speed
#     x = [5, 7, 8, 7, 2, 17, 2, 9, 4, 11, 12, 9, 6]
#     y = [99, 86, 87, 88, 111, 86, 103, 87, 94, 78, 77, 85, 86]
#     slope, intercept, r, p, std_err = stats.linregress(x, y)
#
#     print(r)
#
#     def myfunc(x):
#         # print(f"slope: {slope}, x: {x}, intercept {intercept}")
#         return slope * x + intercept
#
#     my_model = list(map(myfunc, x))
#     # 10 is to rty and predict the speed of a 10 yr old car
#     speed = myfunc(10)
#     plt.scatter(x, y)
#     plt.plot(x, my_model)
#     plt.show()
#     return f"{speed}"

# linear regression
# @ml.route('/machine-learning/', methods=['GET'])
# def machine_learning():
#     age = [5, 7, 8, 7, 2, 17, 2, 9, 4, 11, 12, 9, 6]
#     speed = [99, 86, 87, 88, 111, 86, 103, 87, 94, 78, 77, 85, 86]
#
#     slope, intercept, r, p, std_err = stats.linregress(age, speed)
#
#     def myfunc(x):
#         return slope * x + intercept
#
#     mymodel = list(map(myfunc, age))
#     plt.scatter(age, speed)
#     plt.plot(age, mymodel)
#     plt.show()
#     return 'Hello'

@ml.route('/machine-learning/', methods=['GET'])
def machine_learning():
    # x = age
    # y = speed
    x = [1, 2, 3, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 18, 19, 21, 22]
    y = [100, 90, 80, 60, 60, 55, 60, 65, 70, 70, 75, 76, 78, 79, 90, 99, 99, 100]
    slope, intercept, r, p, std_err = stats.linregress(x, y)
    plt.scatter(x, y)
    plt.show()
    return x
