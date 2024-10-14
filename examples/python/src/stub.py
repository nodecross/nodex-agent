import time
import numpy as np
import random, string
import subprocess
import matplotlib.pyplot as plt
from tqdm import tqdm

from sock import post

experiment = "https_didcomm_vc"
results = {}

def randomname(n):
   randlst = [random.choice(string.ascii_letters + string.digits) for i in range(n)]
   return ''.join(randlst)

for s in tqdm(range(2, 20)):
    key = randomname(2 ** s)
    proc = subprocess.Popen("../../../target/release/nodex-agent", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
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
    v = list(map(lambda x: float(x.decode().strip('dur: ').strip(' us\n')), proc.stdout.readlines()))
    results[key] = np.mean(v)
    print(results[key])

xs = []
ys = []
for k, v in results.items():
   xs.append(float(len(k)))
   ys.append(v)

np.savez(experiment, xs, ys)
fig, ax = plt.subplots()
ax.plot(xs, ys)
fig.savefig(f'{experiment}.png')
plt.close(fig)
