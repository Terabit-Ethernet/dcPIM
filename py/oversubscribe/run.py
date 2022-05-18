import os, os.path
import errno
import sys
import subprocess

remote_load = [0.6, 0.8]

runs = ['pim']
workloads = ['imc10', 'websearch', 'datamining']
#precentage = [  0.10, 0.11, 0.12, 0.13, 0.14, 0.15, 0.16, 0.17, 0.18, 0.19, 0.40, 0.41, 0.42, 0.43, 0.44, 0.45, 0.46, 0.47, 0.48, 0.49, 0.50, 0.51, 0.52, 0.53, 0.54, 0.55, 0.56, 0.57, 0.58, 0.59, 0.60, 0.61, 0.62, 0.63, 0.64, 0.65, 0.66, 0.67, 0.68, 0.69, 0.70, 0.71, 0.72, 0.73, 0.74, 0.75, 0.76, 0.77, 0.78, 0.79, 0.80, 0.81, 0.82, 0.83, 0.84, 0.85, 0.86, 0.87, 0.88, 0.89]
over_subscription = [2]
OUTPUT_FOLDER = "../result/oversubscribe"
DATE = sys.argv[1]

loads = [0.4]
def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc: # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

def safe_open_w(path):
    ''' Open "path" for writing, creating any parent directories as needed.
    '''
    mkdir_p(os.path.dirname(path))
    return open(path, 'w')

# for r in runs:

#     for w in workloads:
#         #  generate conf file
#         for r_load in remote_load:

#             for o in over_subscription:
#                 pros = []
#                 os_ratio = 1.0 / o
#                 load = 0.0
#                 first_time = False
#                 while load <= 1.0 - os_ratio * r_load:
#                     if r == "ruf":
#                         for i in range(2):
#                             for j in range(2):
#                                 confFile = "conf_{0}_{1}_{2}_{3}_{4}_{5}_{6}.txt".format(r, w, i, j, o, load, r_load)
#                                 resultFile = "{0}/{1}/result_{2}_{3}_{4}_{5}_{6}_{7}_{8}.txt".format(OUTPUT_FOLDER,DATE, r, i, j, w, o, load, r_load)
#                                 print confFile
#                                 f = safe_open_w(resultFile)
#                                 p = subprocess.Popen(["../../simulator", "2", confFile],stdout=f)
#                                 pros.append(p)
#                                 f.close()
#                     else:
#                         confFile = "conf_{0}_{1}_{2}_{3}_{4}.txt".format(r, w, o, load, r_load)
#                         resultFile = "{0}/{1}/result_{2}_{3}_{4}_{5}_{6}.txt".format(OUTPUT_FOLDER,DATE, r, w, o, load, r_load)
#                         f = safe_open_w(resultFile)
#                         p = subprocess.Popen(["../../simulator", "2", confFile],stdout=f)
#                         pros.append(p)
#                         f.close()
#                     load += 0.1
#         for p in pros:
#             p.wait()
for r in runs:
    for w in workloads:
        #  generate conf file
        for rl in loads:

            for o in over_subscription:
                pros = []
                os_ratio = 1.0 / o
                r_load = rl
                l_load = 0.4
                first_time = False
                if r == "ruf":
                    for i in range(2):
                        for j in range(2):
                            confFile = "conf_{0}_{1}_{2}_{3}_{4}_{5}_{6}.txt".format(r, w, i, j, o, l_load, r_load)
                            resultFile = "{0}/{1}/result_{2}_{3}_{4}_{5}_{6}_{7}_{8}.txt".format(OUTPUT_FOLDER,DATE, r, i, j, w, o, l_load, r_load)
                            print confFile
                            f = safe_open_w(resultFile)
                            p = subprocess.Popen(["../../simulator", "2", confFile],stdout=f)
                            pros.append(p)
                            f.close()
                elif r == "fastpass":
                    for i in range(2):
                        confFile = "conf_{0}_{1}_{2}_{3}_{4}_{5}.txt".format(r, w, o, l_load, r_load, i)
                        print confFile
                        resultFile = "{0}/{1}/result_{2}_{3}_{4}_{5}_{6}_{7}.txt".format(OUTPUT_FOLDER,DATE, r, w, o, l_load, r_load, i)
                        f = safe_open_w(resultFile)
                        p = subprocess.Popen(["../../simulator", "1", confFile],stdout=f)
                        pros.append(p)
                        f.close()
                else:
                    confFile = "conf_{0}_{1}_{2}_{3}_{4}.txt".format(r, w, o, l_load, r_load)
                    resultFile = "{0}/{1}/result_{2}_{3}_{4}_{5}_{6}.txt".format(OUTPUT_FOLDER,DATE, r, w, o, l_load, r_load)
                    f = safe_open_w(resultFile)
                    p = subprocess.Popen(["../../simulator", "1", confFile],stdout=f)
                    pros.append(p)
                    f.close()
#        for p in pros:
#            p.wait()
