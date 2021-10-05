import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

sns.set_style("whitegrid")



number = [3, 10, 20, 50, 100, 200, 500, 1000]

#Init = [145.77,	268.74,	518.41,	920.64	,1346.03	,1968.09	,2011.45	,4289.71	,6746.73	,8386.15	,10838.39	,12532.34,	15124.65,	18347.79]
Gen = [12.326,
52.032,
111.327,
290.097,
582.094,
1203.731,
3009.284,
5982.481]
Verify = [0.222,
0.884,
1.843,
4.59,
9.276,
20.041,
45.258,
90.434]
#plt.plot(number, Init, color='r', linewidth=2, marker='o', markersize= 5,markevery=np.where(np.array(number) > 0, True, False),label='Initilization', linestyle='--')
plt.plot(number, Gen, color='y',linewidth=2, marker='s', markersize= 5,markevery=np.where(np.array(number) > 0, True, False),label='Proof Generation',linestyle='--')
plt.plot(number, Verify, color='c',linewidth=2, marker='P', markersize= 5,markevery=np.where(np.array(number) > 0, True, False),label='Proof Verification',linestyle='--')

plt.xlabel("Number of Nodes")

plt.ylabel("Time (s)")
plt.legend(loc = 'best')
plt.savefig('eval.png', bbox_inches='tight')



'''

FL250 = [492.447, 12766.25, 601.01, 91.4]
FL500 = [492.447, 25532.5, 1861.29, 92.1]
FL1000 = [492.447, 51065, 2764.59, 102.1]

ind = np.arange(4)
width = 0.15

plt.plot(ind, FL250, color='c', linewidth=1.0, linestyle='-', marker='o', markevery=ind, label='250 Learners')

plt.plot(ind, FL500, color='y', linewidth=1.0, linestyle='-', marker='s', markevery=ind, label='500 Learners')

plt.plot(ind, FL1000, color='r', linewidth=1.0, linestyle='-', marker='P', markevery=ind, label='1000 Learners')

plt.xticks(ind, ('Enc', 'Re-enc', 'Eval', 'Dec'))


plt.ylabel("Time (ms)")

plt.legend(framealpha=1, loc = 'best')


plt.savefig('fl-part.png')


'''




