#!python
#-*- coding:utf-8 -*-

import os,sys,base64,hashlib,time
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


def KeysNew(bit = 2048):

    rnd_generator = Random.new().read

    rsa = RSA.generate(bit,rnd_generator)

    secret_pem = rsa.exportKey()
    public_pem = rsa.publickey().exportKey()

    if not os.path.exists('ssl'):

        os.mkdir('ssl')

    with open('ssl/secret.pem','wb') as file:

        file.write(secret_pem)
        
    with open('ssl/public.pem','wb') as file:

        file.write(public_pem)
        
    print('finish export pem files')



def encrypt(strtxt):

    with open('ssl/public.pem','r') as file:

        rsakey = RSA.importKey(file.read())
        cipher = PKCS1_v1_5.new(rsakey)

        enctxt = base64.b64encode(cipher.encrypt(strtxt.encode(encoding = 'utf-8')))
        
        return enctxt
       
    
def decrypt(strtxt):

    with open('ssl/secret.pem','r') as file:
    
        rsakey = RSA.importKey(file.read())
        cipher = PKCS1_v1_5.new(rsakey)
        
        dectxt = cipher.decrypt(base64.b64decode(strtxt),'ERROR')
        
        return dectxt


def calmd5(strtxt):

    md5gen = hashlib.md5()
    md5gen.update(strtxt)
    return(md5gen.hexdigest())

def test(root = '.'):

    def recursion(mpath):
    
        if os.path.isfile(mpath):
        
            return ['{0}-{1}'.format(os.path.relpath(mpath,root),os.path.getsize(mpath))]

        elif os.path.isdir(mpath):
        
            lst = os.listdir(mpath)
            tmp = []
            
            for x in lst:
            
                fpath = os.path.join(mpath,x)
                
                tmp.extend(recursion(fpath))
                
            return tmp

            
    filelist = recursion(root)

    print u'\n总共{0}个文件'.format(len(filelist))
    md5list = [calmd5(x) for x in filelist]

    md5list.sort()
    
    strtxt = ','.join(md5list)

    md5str = calmd5(strtxt)
    
    enctxt = encrypt(md5str)
    
    print u'\n原始字符串:',md5str
    
    print u'\n加密字符串:',enctxt
    
    print u'\n解密字符串:',decrypt(enctxt)
    

if __name__ == '__main__':

    start = time.time()

    if not os.path.exists('ssl'):
    
        KeysNew()
        
    test()
    
    print(u'\n用时{0}s'.format(time.time()-start))
