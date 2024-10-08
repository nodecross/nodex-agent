# cat tcp_vc.txt| sed 's/dur: //' | sed 's/ us//' > tcp_vc_clean.txt
import numpy as np
import sys

args = sys.argv

arr = np.loadtxt(args[1])

print('mean', np.mean(arr), 'us')
print('std', np.std(arr))
