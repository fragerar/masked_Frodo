import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import norm

gadgets = ["AB", "BA", "AND", "ADD", "ZERO"]
alpha = 10**(-5) # error rate

def display_results(arch, nb_traces):
    if arch == 'asm':
        samples = {"AB": 1200, "BA": 600, "AND": 600, "ADD": 1100, "ZERO": 1200}
    elif arch == 'naive_asm':
        samples = {"AB": 600, "BA": 300, "AND": 300, "ADD": 700, "ZERO": 600}
    elif arch == 'c':
        samples = {"AB": 500, "BA": 200, "AND": 300, "ADD": 500, "ZERO": 500}

        
    

    for GADGET in gadgets:
        sigma = 1 - (1 - alpha)**(1/samples[GADGET])
        th = norm.ppf(1 - sigma/2) # we adapt the threshold depending on number of samples

        t_test = np.load("t-test-{}-{}-{}.npy".format(str(nb_traces), GADGET, arch))
        y_max = (max(50, max(abs(t_test))))
        plt.ylim(-y_max, y_max)
        plt.plot(t_test[0:samples[GADGET]], linewidth=0.5)
        plt.plot([th]*samples[GADGET], color = 'r')
        plt.plot([-th]*samples[GADGET], color='r')
        plt.text(samples[GADGET]*1/20, th+y_max/20, "threshold: " + str(round(th,1)), fontsize=12)
        plt.savefig('t-test-{}-{}-{}.png'.format(str(nb_traces), GADGET, arch))
        plt.close()

display_results('asm', 100000)
display_results('c', 5000)
display_results('naive_asm', 5000)
