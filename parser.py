'''
Created on Feb 26, 2010

@author: rob
'''
from numpy import *
import sys

pbs_bank = []
pbs_verify = []
mcl_ecpbs_bank = []
mcl_ecpbs_verify = []
gmp_pbs_bank = []
gmp_pbs_verify = []
def main():
    filename = sys.argv[1]
    if filename.find(".gz") > -1:
        import gzip
        file = gzip.open(filename)
    else:
        file = open(filename)
    for line in file:
        parts = line.split()
        if len(parts) < 5: continue
        if line.find("mcl_ecpbs Bank") > -1:
            mcl_ecpbs_bank.append(long(parts[5]))
        elif line.find("mcl_ecpbs Signature") > -1:
            mcl_ecpbs_verify.append(long(parts[5]))
        elif line.find("gmp_pbs Bank") > -1:
            gmp_pbs_bank.append(long(parts[5]))
        elif line.find("gmp_pbs Signature") > -1:
            gmp_pbs_verify.append(long(parts[5]))
        elif line.find("pbs Bank") > -1:
            pbs_bank.append(long(parts[5]))
        elif line.find("pbs Signature") > -1:
            pbs_verify.append(long(parts[5]))
        
    print "pbs_bank:", stat(pbs_bank)
    print "pbs_verify:", stat(pbs_verify)
    print "mcl_ecpbs_bank:", stat(mcl_ecpbs_bank)
    print "mcl_ecpbs_verify:", stat(mcl_ecpbs_verify)
    print "gmp_pbs_bank:", stat(gmp_pbs_bank)
    print "gmp_pbs_verify:", stat(gmp_pbs_verify)

def stat(list):
    return "max:" + str(max(list)) + ",min:" + str(min(list)) + ",mean:" + str(mean(list)) + ",median:" + str(median(list)) + ",std:" + str(std(list))
    
if __name__ == '__main__':
    main()
