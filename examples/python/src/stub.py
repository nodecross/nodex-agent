import time
import numpy as np
import random, string
import subprocess
import matplotlib.pyplot as plt

from sock import post

experiment = "tls_didcomm"
results = {}

def randomname(n):
   randlst = [random.choice(string.ascii_letters + string.digits) for i in range(n)]
   return ''.join(randlst)

for s in range(2, 12):
    key = randomname(2 ** s)
    proc = subprocess.Popen("../../../target/debug/nodex-agent", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    time.sleep(5)
    for _ in range(100):
        json_response = post(
            "/custom_metrics",
            {
                "key": key,
                "value": 10.52,
                "occurred_at": str(int(time.time())),
            },
        )
    time.sleep(5)
    proc.kill()
    results[key] = proc.stdout.readlines()

xs = []
ys = []
for k, v in results.items():
   xs.append(float(len(k)))
   v = list(map(lambda x: float(x.decode().strip('dur: ').strip(' us\n')), v))
   ys.append(np.mean(v))

np.savez(experiment, xs, ys)
fig, ax = plt.subplots()
ax.plot(xs, ys)
fig.savefig(f'{experiment}.png')
plt.close(fig)
