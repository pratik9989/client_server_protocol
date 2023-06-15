import socket
import json
import random
import string
import hashlib
import ssl
import uuid
import sys
import os

# external Library
import jwt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

keyFile = "./priv.pem"  # provide full path to the private key file location
certFile = "./cert.crt"  # provide full path to the Certificate file location


def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


# user credentials
userData = {"username":'test', "password":'test', "name":'client1', "id":1}
authencationKey = get_random_string(16)
# we do not need to chnage initial vector everytime
IV = str.encode(get_random_string(16))
KEY = None
obj_enc = None


def inatilizeEnyryption(IV=IV):
    # this will convert any pnemonic string which the user wants to choose as password to a 32 bit encrypted object
    key_random_string = uuid.uuid4().hex
    key = hashlib.sha256(str.encode(key_random_string)).digest()
    # IV = b"ddljekwevcrsxyau"  # Initialization vector should always be 16 bit
    # creating an object to encrypt our data with
    enc = AES.new(key, AES.MODE_CFB, IV)
    return key, enc

# add one more layer of encryption(we add 1269 in cinverted integer, so if attacker get data then he/she can not decode exact value)
def patternToEncrypt(val):
    return (val + 1269)

def varifyTokenAndSession(clientRequest, sessions, clientAddress):
    session = [s for s in sessions if s['id'] == clientRequest['data']['sessionId']]
    if(len(session)>0 and session[0]['ip'] != clientAddress):
        raise Exception('Client IP address does not match with the IP address stored in session')
    return jwt.decode(clientRequest['header']['token'], key=authencationKey, algorithms=['HS256', ])

def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5000  # initiate port no above 1024
    messages = []
    confirmedClients = []
    sessions = []
    # session Id will be auto incremented
    lastSessionId = 0
    try:
        s_socket = socket.socket()  # get instance
        # look closely. The bind() function takes tuple as argument
        s_socket.bind((host, port))  # bind host address and port together
        server_socket = ssl.wrap_socket(
            s_socket, keyfile=keyFile, certfile=certFile, server_side=True)
        # the above function "wraps" the socket created with the security layer of signed certificate, private key
        # The parameter server_side is a boolean which identifies whether server-side or client-side behavior is desired from this socket, true specifies server behaviour.
    except Exception as e:
        if(type(e).__name__ == 'SSLError'):
            print('Exception: Please enter valid SSL Password(PEM pass phrase)')
        else:    
            print(f'Exception: {type(e).__name__}', str(e))
        sys.exit()
        

    print(f"Server started on HOST={host} Port={port}")
    print('waiting for client')

    # configure how many client the server can listen simultaneously
    server_socket.listen(1)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    print('\n')
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        clientData = conn.recv(1024)
        clientData = clientData.decode("utf-8")
        if not clientData:
            # if clientData is not received break
            break
        json_acceptable_string = clientData.replace("'", "\"")
        clientDataDict = json.loads(json_acceptable_string)
        # append client request in messages list
        messages.append(clientDataDict)
        # print("from connected user: " + str(clientDataDict['data']['message-type']))
        print('Received:', json.dumps(clientDataDict, indent=4))
        print('\n')

        # make response data dictionary
        responseData = {
            "header":{},
            "data":{
                "sequesce": clientDataDict['data']['sequence']
            }
        }

        # reply = input(' -> ')

        # If request contain unvalid sesssion id then authencate user and add new session
        if ((not 'sessionId' in clientDataDict['data'])):
            
            # check username and password received from client
            if((not 'username' in clientDataDict['data']) or (not 'password' in clientDataDict['data']) or (('username' in clientDataDict['data'] and clientDataDict['data']['username'] != userData["username"]) or ('password' in clientDataDict['data'] and clientDataDict['data']['password'] != userData["password"])) ):
                print('Authencation Failed')
                # Authencation Failes, Username or password not matched
                responseData['data']['isAuthencatedUser'] = 'false'
                responseData['data']['message-type'] = 'CLOSE'
            else:
                # call initialize encryption for first time
                key, enc = inatilizeEnyryption()
                KEY = key
                obj_enc = enc
                payload = {
                    'name':userData['name'],
                    'id':userData['id']
                }
                # generate jwt token
                token = jwt.encode(
                    payload=payload,
                    key=authencationKey
                )
                confirmedClients.append(address[0])
                lastSessionId = lastSessionId+1
                sessions.append({"id":(lastSessionId), "mac":clientDataDict['header']['MAC'], "ip":address[0]})
                responseData['data']['sessionId'] = lastSessionId

                responseData['data']['message-type'] = f"{str(clientDataDict['data']['message-type'])}_ACK"
                responseData['data']['isAuthencatedUser'] = 'True'
                responseData['data']['key1'] = patternToEncrypt(int.from_bytes(KEY, "big"))
                responseData['data']['key2'] = patternToEncrypt(int.from_bytes(IV, "big"))
                responseData['data']['token'] = token

        # If sessionid doed not match and user has not pass username and password
        elif(('sessionId' in clientDataDict['data']) and (len([session for session in sessions if (('id' in session) and (session['id'] == clientDataDict['data']['sessionId']))]) < 1)):
            print('Exception: Session Id does not match')
            # Authencation Failes, Username or password not matched
            responseData['data']['isAuthencatedUser'] = 'false'
            responseData['data']['message-type'] = 'CLOSE'

        else:
            # hand shaking is done
            # varify token
            try:
                user = varifyTokenAndSession(clientDataDict, sessions, address[0])
                if (clientDataDict['data']['message-type'] == 'DATA_REQUEST'):
                
                    responseData['data']['sessionId'] = clientDataDict['data']['sessionId']
                    # regenerate encryption key after 10 data response
                    if ((int(clientDataDict['data']['sequence']) - 1) % 10 == 0):
                        key, enc = inatilizeEnyryption()
                        KEY = key
                        obj_enc = enc
                        responseData['data']['key1'] = patternToEncrypt(
                            int.from_bytes(KEY, "big"))
                    responseData['data']['message-type'] = 'DATA_RESPONSE'
                    # encrypting the data to be sent using the AES object we created
                    string = get_random_string(8)
                    print('Plain text data', string)
                    # padding adds empty bytes to the end of your string until it’s the correct number of bytes long. block_size is 16 byte
                    encrypted = obj_enc.encrypt(pad(string.encode('utf-8'), AES.block_size))

                    # convert the encryted data from byte to int
                    byteToInt = int.from_bytes(encrypted, "big")
                    responseData['data']['data'] = patternToEncrypt(byteToInt)
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(f'Exception: {str(e)}. file: {fname} line: {exc_tb.tb_lineno}')
                # close connection
                responseData['data']['message-type'] = 'CLOSE'

        # append server response in messages list
        if (('isConnectionClose' in clientDataDict['data']) and clientDataDict['data']['isConnectionClose'] == 'True'):
            print('receive connection close request from client, so terminate session')
            break
        messages.append(responseData)
        print('Sending:', json.dumps(responseData, indent=4))
        # send data to the client
        conn.send(bytes(str(responseData), encoding="utf-8"))
    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
