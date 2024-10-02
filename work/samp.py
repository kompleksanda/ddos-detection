import random

values = [random.weibullvariate(1/4, 1) for i in range(2000)]


import matplotlib.pyplot as plt

plt.hist(values, 200, density=True)
#plt.plot(range(len(values)), values)
plt.show()