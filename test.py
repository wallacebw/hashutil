import multiprocessing
from multiprocessing.pool import ThreadPool
import time



def track_job(job, update_interval=1):
    while job._number_left > 0:
        print(f"\rTasks remaining = {job._number_left * job._chunksize}", end="")
        time.sleep(update_interval)



def hi(x, text): #This must be defined before `p` if we are to use in the interpreter
    time.sleep(x//8)
    return x, text

arguments = [None] * 50
for i, argument in enumerate(arguments):
    arguments[i] = [i, i*i]

p   = ThreadPool()

res = p.starmap_async(hi, arguments, chunksize=1)

track_job(res,update_interval=0.4)
results = res.get()
print(results)
