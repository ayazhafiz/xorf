# See analysis/plot_zeroes

import matplotlib.pyplot as plt

with open('zeroes.txt', 'r') as f:
    x = [int(v) for v in f.readlines()]

plt.xlabel('Sample')
plt.ylabel('Zeroes in 2000 element window')
plt.plot(x)
plt.show()
