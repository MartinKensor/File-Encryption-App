#take message string
#encrypt and print
#decrypt and print

import random
import pickle

#Open file function ---- takes filename string 
def open_file(filename):
	file = open(filename, "rb")
	byte = file.read(8)
	byte2hex=byte
	while byte:
		byte = file.read(8)
		byte2hex+=byte
	file.close()
	plaintext=byte2hex.hex().upper()

    #returns a hex string of file data (converted from byte to hex)
	return plaintext 

# Hexadecimal to binary conversion
def hex2bin(s):
	mp = {'0' : "0000",
		'1' : "0001",
		'2' : "0010",
		'3' : "0011",
		'4' : "0100",
		'5' : "0101",
		'6' : "0110",
		'7' : "0111",
		'8' : "1000",
		'9' : "1001",
		'A' : "1010",
		'B' : "1011",
		'C' : "1100",
		'D' : "1101",
		'E' : "1110",
		'F' : "1111",
		' ' : "100000"
  }
	bin = ""
	for i in range(len(s)):
		bin = bin + mp[s[i]]
	return bin
	
# Binary to hexadecimal conversion
def bin2hex(s):
	mp = {"0000" : '0',
		"0001" : '1',
		"0010" : '2',
		"0011" : '3',
		"0100" : '4',
		"0101" : '5',
		"0110" : '6',
		"0111" : '7',
		"1000" : '8',
		"1001" : '9',
		"1010" : 'A',
		"1011" : 'B',
		"1100" : 'C',
		"1101" : 'D',
		"1110" : 'E',
		"1111" : 'F',
		"100000" : ' '
  }
	hex = ""
	for i in range(0,len(s),4):
		ch = ""
		ch = ch + s[i]
		ch = ch + s[i + 1]
		ch = ch + s[i + 2]
		ch = ch + s[i + 3]
		hex = hex + mp[ch]
		
	return hex

#HELPER FUNCTION: check if numbers are coprime --- int argument
def gcd(a,b):
    while b != 0:
        a, b = b, a % b
    return a

#HELPER FUNCTION: check if integers are primes --- int argument
def isPrime(numb):
    if numb == 2:
        return True
    if numb < 2 or numb % 2 == 0:
        return False
    for n in range(3, int(numb**0.5)+2, 2):
        if numb % n == 0:
            return False
    return True

#list of prime numbers global variable
primes = [i for i in range(0,100000) if isPrime(i)]

#HELPER FUNCTION: finding d -- int arg
def mod_inverse(a,b):
    x1=0
    x2=1
    y1=1
    y2=0
    a_unchanged=a
    b_unchanged=b

    while b !=0:
        q=a//b
        r=a-(q*b)
        x=x2-(q*x1)
        y=y2-(q*y1)
        a=b
        b=r
        x2=x1
        x1=x
        y2=y1
        y1=y
    if x2<0:
        x2+=b_unchanged
    if y2<0:
        y2+=a_unchanged
    return x2


#Generate a pair of public and private keys
def create_keys():
    p = random.choice(primes)
    q = random.choice(primes)
    while p==q:
        q=random.choice(primes)
    #find n
    n = p*q

    phi=(p-1)*(q-1)

    #find e such that e and phi are coprime
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    #find d
    d = mod_inverse(e, phi)

    #return public and private key tuples
    return ((e,n),(d,n))


#Function to encrypt plaintext; --- tuple(publicKey) and hex string (plainText)
def encrypt(publicKey, filename):
    e, n = publicKey
    plainText=open_file(filename)

    #apply RSA ecnryption equation: (message^e)mod n
    cipherText = [(ord(char) ** e) % n for char in plainText]

    with open(filename, "wb") as f:
        pickle.dump(cipherText,f)
    
    #return list of integers
    return 


#function to decrypt ciphertext--- tuple(privateKey) and hex string (cipherText)
def decrypt(privateKey, filename):
    
    with open(filename, "rb") as f:
        cipherText= pickle.load(f)
    
    d, n = privateKey

    #apply RSA decryption equation: (message^d)mod n
    plainText = [chr((char ** d) % n) for char in cipherText]
    with open(filename, "wb") as f:
        f.write(bytes.fromhex(''.join(plainText)))

    #return hex string
    return 


#### RUN PROGRAM ####------------------------

#publicKey=(1063, 1643)
#privateKey=(1447,1643)
#encrypt(publicKey,"1a.jpg")
#decrypt(privateKey,"1a.jpg")

